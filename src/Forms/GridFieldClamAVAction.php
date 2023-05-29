<?php

namespace Symbiote\SteamedClams\Forms;

use LogicException;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\GridField\GridField;
use SilverStripe\Forms\GridField\GridField_ActionProvider;
use SilverStripe\Forms\GridField\GridField_ColumnProvider;
use SilverStripe\Forms\GridField\GridField_FormAction;
use SilverStripe\ORM\DataObject;
use Symbiote\SteamedClams\ClamAV;
use Symbiote\SteamedClams\Model\ClamAVScan;

class GridFieldClamAVAction implements GridField_ColumnProvider, GridField_ActionProvider
{
    /**
     * @var ClamAV|null
     */
    protected $clamAV = null;

    /**
     * {@inheritdoc}
     */
    public function __construct()
    {
        $this->clamAV = Injector::inst()->get(ClamAV::class);
    }

    /**
     * {@inheritdoc}
     */
    public function augmentColumns($gridField, &$columns)
    {
        if (!in_array('Actions', $columns)) {
            $columns[] = 'Actions';
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getColumnAttributes($gridField, $record, $columnName)
    {
        return ['class' => 'clamav-buttons'];
    }

    /**
     * {@inheritdoc}
     */
    public function getColumnMetadata($gridField, $columnName)
    {
        return ['title' => ''];
    }

    /**
     * {@inheritdoc}
     */
    public function getColumnsHandled($gridField)
    {
        return ['Actions'];
    }

    /**
     * @param GridField $gridField
     * @param DataObject $record
     * @param string $columnName
     *
     * @return string - the HTML for the column
     */
    public function getColumnContent($gridField, $record, $columnName)
    {
        if (!$record->exists()) {
            return;
        }
        switch ($columnName) {
            case 'Actions':
                $state = $record->State;

                $fieldList = FieldList::create();
                if (!$record->IsScanned && $record->File()->exists()) {
                    $field = GridField_FormAction::create(
                        $gridField,
                        'clamav_scan' . $record->ID,
                        'Scan',
                        'clamav_scan',
                        ['RecordID' => $record->ID]
                    );
                    $field->addExtraClass('ss-ui-action-constructive clamav-button');
                    if ($this->clamAV->isOffline()) {
                        $field->setDisabled(true);
                    }
                    $fieldList->push($field);
                }
                if ($state === ClamAVScan::STATE_INFECTED || $state === ClamAVScan::STATE_UNSCANNED) {
                    $field = GridField_FormAction::create(
                        $gridField,
                        'clamav_ignore' . $record->ID,
                        'Ignore',
                        'clamav_ignore',
                        ['RecordID' => $record->ID]
                    );
                    $field->addExtraClass('clamav-delete-button clamav-button');
                    $fieldList->push($field);
                }

                return $fieldList->forTemplate();
                break;

                /*case 'clamav_ignore':
                $state = $record->State;
                if ($state !== ClamAVScan::STATE_INFECTED && $state !== ClamAVScan::STATE_UNSCANNED) {
                    return;
                }
                $field = GridField_FormAction::create(
                    $gridField,
                    $columnName.$record->ID,
                    'Ignore',
                    $columnName,
                    array('RecordID' => $record->ID)
                );
                $field->addExtraClass('clamav-delete-button');
                return $field->Field();
            break;*/

            default:
                throw new LogicException('Unsupported column name "' . $columnName . '"');
                break;
        }
    }

    /**
     * Handle the actions and apply any changes to the GridField
     *
     * @param GridField $gridField
     * @param string $actionName
     * @param mixed $arguments
     * @param array $data - form data
     *
     * @return void
     */
    public function handleAction(GridField $gridField, $actionName, $arguments, $data)
    {
        $actions = $this->getActions(null);
        if (!in_array($actionName, $actions)) {
            return;
        }
        switch ($actionName) {
            case 'clamav_scan':
                $record = $gridField->getList()->byID($arguments['RecordID']);
                if (!$record) {
                    return;
                }
                if ($record->processFileActionScan()) {
                    $this->notify('Scanned file.');

                    return;
                }
                $this->notify('Unable to scan file.');

                return;
                break;

            case 'clamav_ignore':
                $record = $gridField->getList()->byID($arguments['RecordID']);
                if (!$record) {
                    return;
                }
                if (!$record->processFileActionIgnore()) {
                    $this->notify('Failed to process ignore action on file.');

                    return;
                }
                $this->notify('Ignored file.');

                return;
                break;

            default:
                throw new LogicException('Invalid action "' . $actionName . '".');
                break;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getActions($gridField)
    {
        return ['clamav_ignore', 'clamav_scan'];
    }

    /**
     * Notify end user of the result of an action
     *
     * @param string $message
     *
     * @return boolean
     */
    protected function notify($message)
    {
        $controller = Controller::has_curr() ? Controller::curr() : null;
        if (!$controller) {
            return;
        }
        $controller->getResponse()->addHeader('X-Status', rawurlencode($message));

        return true;
    }
}
