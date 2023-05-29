<?php

namespace Symbiote\SteamedClams;

use LogicException;
use Psr\Log\LoggerInterface;
use SilverStripe\Assets\File;
use SilverStripe\Assets\Folder;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\ArrayList;
use SilverStripe\ORM\DataList;
use SilverStripe\ORM\DataObject;
use Symbiote\SteamedClams\Model\ClamAVScan;

use \ClamdBase;
use \ClamdPipe;
use \ClamdException;
use \ClamdSocketException;

use \Exception;


class ClamAV
{
    use Injectable;
    use Configurable;

    /**
     * @var string
     */
    const MODULE_DIR = 'steamedclams';

    /**
     * If ClamAV daemon can't be connected to or is offline.
     *
     * @var bool
     */
    const OFFLINE = false;

    /**
     * If the scan is using the Clamd socket or clamdscan binary
     *
     * @var bool
     */
    const USE_SOCKET = true;

    /**
     * Configure this to ignore `File` records created before the date
     * provided.
     *
     * eg. You installed this module on a 5 year old website and to avoid a bulky
     *       amount of `ClamAVScan` records from `ClamAVInstallTask`, you're just opting
     *       to not scan those old files for viruses
     *
     * @var string
     */
    private static $initial_scan_ignore_before_datetime = '1970-12-25 00:00:00';

    /**
     * If enabled, if ClamAV daemon isn't running or isn't installed
     * the file will be denied as if it has a virus.
     *
     * @var bool
     */
    private static $deny_on_failure = false;

    /**
     * Settings that must be identical to your clamd.conf file.
     *
     * @config
     * @var array
     */
    private static $clamd = [
        // Path to a local socket file the daemon will listen on.
        // Default: disabled (must be specified by a user)
        'LocalSocket' => '/var/run/clamav/clamd.ctl',
        'LocalBinary' => '/usr/bin/clamdscan'
    ];

    /**
     * @var ClamdBase|ClamAVScanner|null
     */
    protected $clamd_instance = null;

    /**
     * @var ClamdException|Exception|null
     */
    protected $last_exception = null;

    /**
     * @var boolean|null
     */
    protected $_cache_isOffline = null;

    /**
     * @param File $file
     *
     * @return ClamAVScan|null
     */
    public function scanFileRecordForVirus(File $file)
    {
        $isFileMaybeExternal = false;
        $fileMetaData = $file->File->getMetadata();
        $filepath = $file->getFullPath();

        if (!file_exists($filepath)) {
            // If file can't be found, attempt to download
            // from external CDN or similar.
            $isFileMaybeExternal = true;
            $this->beforeHandleMissingFile($file);

            return null;
        }

        $record = $this->scanFileForVirus($filepath);
        if ($record && $record instanceof DataObject) {
            $record->FileID = $file->ID;
        }
        if ($isFileMaybeExternal) {
            // If file was downloaded from external CDN
            // or similar, delete the file / cleanup.
            $this->afterHandleMissingFile($file);
        }

        return $record;
    }

    /**
     * If file doesn't exist on local machine, try to download from a CDN module or similar.
     *
     * @param File $file
     *
     * @return boolean|null
     */
    public function beforeHandleMissingFile(File $file)
    {
        $result = null;

        // Support CDN module 'CDNFile' extension
        if ($file->hasMethod('downloadFromContentService')) {
            $result = $result || $file->downloadFromContentService();
        }

        // note(Jake): Perhaps add extension here to support other modules

        return $result;
    }

    public function verifyClamAVConfig()
    {
        $useBinary = Config::inst()->get(__CLASS__, 'use_clamscan');
        $clamdConf = Config::inst()->get(__CLASS__, 'clamd');

        $localSocket = isset($clamdConf['LocalSocket']) ? $clamdConf['LocalSocket'] : '';
        $localBinary = isset($clamdConf['LocalBinary']) ? $clamdConf['LocalBinary'] : '';

        switch (true) {
            case !$useBinary && !$localSocket: {
                // need Local Socket set
                throw new LogicException(
                    'When using LocalSocket, empty value for "clamd.LocalSocket" config not allowed.'
                );
            }
            break;

            case $useBinary && !$localBinary: {
                // Need Local Binary set
                throw new LogicException(
                    'When using LocalBinary, empty value for "clamd.LocalBinary" config not allowed.'
                );
            }
            break;

            default: {
                return true;
            }
        }
    }

    /**
     * @return ClamAVScan|null
     */
    public function scanFileForVirus($filepath)
    {
        $this->verifyClamAVConfig();

        $scanResult = $this->fileScan($filepath);

        if ($scanResult === self::OFFLINE) {
            $record = ClamAVScan::create();
            $record->Filename = $filepath;
            $record->IPAddress = $this->getIP();
            $record->setRawData($scanResult);

            return $record;
        }

        $stats = ($scanResult && isset($scanResult['stats'])) ? $scanResult['stats'] : null;

        $filename = ($scanResult && isset($scanResult['file'])) ? $scanResult['file'] : null;
        if ($stats === null || $filename === null) {
            throw new LogicException('Expected an array with "stats" and "file" as key.');
        }

        $record = ClamAVScan::create();
        $record->Filename = $filepath;
        $record->IPAddress = $this->getIP();
        $record->IsScanned = 1;
        $record->IsInfected = ($stats !== 'OK');
        $record->setRawData($scanResult);

        return $record;
    }

    /**
     * Scan for virus, return array() if ClamAV daemon is running and
     * returns false if it is not (or an error occurred connecting to the socket)
     *
     * @param string $filepath
     *
     * @return array|false
     */
    protected function fileScan($filepath)
    {
        $this->last_exception = null;

        try {
            $clamd = $this->getClamd();
            $scanResult = $clamd->fileScan($filepath);
        } catch (ClamdSocketException $e) {
            $this->setLastExceptionAndLog($e);
            $scanResult = self::OFFLINE;
        } catch (Exception $e) {
            $this->setLastExceptionAndLog($e);
            $scanResult = self::OFFLINE;
        }

        return $scanResult;
    }

    /**
     * Return underlying Clamd implementation.
     *
     * @return ClamdBase|ClamAVScanner
     */
    protected function getClamd()
    {
        if ($this->clamd_instance) {
            return $this->clamd_instance;
        }

        $useBinary = Config::inst()->get(__CLASS__, 'use_clamscan');

        if ($useBinary) {
            return $this->clamd_instance = $this->getScanner();
        }

        return $this->clamd_instance = $this->getClamdPipe();
    }

    /**
     * Return ClamAV Scanner class
     *
     * @return ClamAVScanner
     */
    protected function getScanner()
    {
        $clamdConf = Config::inst()->get(__CLASS__, 'clamd');
        $localBinary = isset($clamdConf['LocalBinary']) ? $clamdConf['LocalBinary'] : '';

        $result = null;

        if (class_exists(Injector::class)) {
            $result = Injector::inst()->create(ClamAVScanner::class, $localBinary);
        } else {
            $result = new ClamAVScanner($localBinary);
        }

        return $result;
    }

    /**
     * Return ClamdBase class
     *
     * @return ClamdBase
     */
    protected function getClamdPipe()
    {
        $clamdConf = Config::inst()->get(__CLASS__, 'clamd');
        $localSocket = isset($clamdConf['LocalSocket']) ? $clamdConf['LocalSocket'] : '';

        $result = null;
        if (class_exists(Injector::class)) {
            $result = Injector::inst()->create(ClamdPipe::class, $localSocket);
        } else {
            $result = new ClamdPipe($localSocket);
        }

        return $result;
    }

    /**
     * Set exception, if it has a non-falsey value, log it.
     */
    protected function setLastExceptionAndLog(\Exception $e)
    {
        if ($e) {
            Injector::inst()->get(LoggerInterface::class)->warning('Query executed: ' . $e->getMessage());
        }
        $this->last_exception = $e;
    }

    /**
     * Get the current users IP address
     *
     * @return string
     */
    protected function getIP()
    {
        if (!Controller::has_curr()) {
            if (Director::is_cli()) {
                // If running from command line, you can assume it's
                // the local machine.
                return '127.0.0.1';
            }

            return '';
        }
        $request = Controller::curr()->getRequest();
        if (!$request) {
            return '';
        }

        return $request->getIP();
    }

    /**
     * If file didn't exist on local machine and downloaded from CDN, we want to re-remove it.
     *
     * @param File $file
     *
     * @return boolean|null
     */
    public function afterHandleMissingFile(File $file)
    {
        $result = null;

        // Support CDN module 'CDNFile' extension
        if ($file->hasMethod('deleteLocalIfExistsOnContentService')) {
            //$this->log('Removing '.$file->ClassName.' #'.$file->ID.' from local machine -IF- it exists on CDN...');
            $result = $result || $file->deleteLocalIfExistsOnContentService();
        }

        // note(Jake): Perhaps add extension here to support other modules

        return $result;
    }

    /**
     * Get list of files that haven't been checked at all.
     * ie. before installation of module
     *
     * @return DataList|Arraylist
     */
    public function getInitialFileToScanList()
    {
        $excludeFileIDs = ClamAVScan::get()->column('FileID');
        $excludeFileIDs = array_unique($excludeFileIDs);
        $list = $this->getBaseFileList();
        if (!$list) {
            return new Arraylist();
        }

        if (!empty($excludeFileIDs)) {
            $list = $list->filter([
                'ID:not' => $excludeFileIDs,
            ]);
        }
        $ignoreBeforeDatetime = Config::inst()->get(__CLASS__, 'initial_scan_ignore_before_datetime');
        if ($ignoreBeforeDatetime) {
            $list = $list->filter([
                'Created:GreaterThanOrEqual' => $ignoreBeforeDatetime,
            ]);
            //Debug::dump(SS_Datetime::now()); Debug::dump($ignoreBeforeDatetime); Debug::dump($list->count()); exit;
        }

        return $list;
    }

    /**
     * @return DataList
     */
    public function getBaseFileList()
    {
        $list = File::get();
        $list = $list->filter([
            'ClassName:not' => Folder::class,
        ]);

        return $list;
    }

    /**
     * Get list of files that couldn't be scanned when uploaded
     * due to ClamAV daemon being down or not properly configured
     * ie. after installation of module
     *
     * @return ArrayList|DataList
     */
    public function getFailedToScanFileList()
    {
        $scanList = ClamAVScan::get();
        $scanList = $scanList->filter([
            'IsScanned'  => 0,
            'Action'     => ClamAVScan::ACTION_NONE,
            'FileID:not' => 0,
        ]);
        $fileIDs = $scanList->column('FileID');
        $fileIDs = array_unique($fileIDs);
        if (!$fileIDs) {
            return new ArrayList();
        }
        $list = $this->getBaseFileList();
        if (!$list) {
            return new ArrayList();
        }
        $list = $list->filter([
            'ID' => $fileIDs,
        ]);

        return $list;
    }

    /**
     * @return boolean
     */
    public function isOffline()
    {
        if ($this->_cache_isOffline !== null) {
            return $this->_cache_isOffline;
        }
        $result = $this->ping();
        $result = ($result === ClamAV::OFFLINE);

        return $this->_cache_isOffline = $result;
    }

    /**
     * Sends a ping to the clamd service returning a bool
     *
     * @return bool
     */
    public function ping()
    {
        try {
            $clamd = $this->getClamd();

            $ping = $clamd->ping();
        } catch (ClamdSocketException $e) {
            $this->setLastExceptionAndLog($e);
            $ping = self::OFFLINE;
        } catch (Exception $e) {
            $this->setLastExceptionAndLog($e);
            $ping = self::OFFLINE;
        }

        return $ping;
    }

    /**
     * @return bool|string
     */
    public function version()
    {
        $this->last_exception = null;

        try {
            $clamd = $this->getClamd();

            $version = $clamd->version();
        } catch (ClamdSocketException $e) {
            $this->setLastExceptionAndLog($e);
            $version = self::OFFLINE;
        } catch (Exception $e) {
            $this->setLastExceptionAndLog($e);
            $version = self::OFFLINE;
        }

        return $version;
    }

    /**
     * Get the last exception caught by this.
     * Allows you to report the exact error to an admin/developer user in the CMS.
     *
     * @return ClamdException|Exception|null
     */
    public function getLastException()
    {
        return $this->last_exception;
    }
}
