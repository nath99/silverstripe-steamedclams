<?php

namespace Symbiote\SteamedClams;

use Avasil\ClamAv\Result;
use Avasil\ClamAv\Scanner;

class ClamAVScanner extends Scanner
{
    function __construct(string $binary)
    {
        $options = [
            'driver' => 'clamscan',
            'executable' => $binary
        ];

        parent::__construct($options);
    }

    /**
     * Scan a file using the Avasil\ClamAv\Scanner
     * return data structured like the Clamd class
     *
     * @param string $file
     * @return array
     */
    public function fileScan($file)
    {
        $stats = 'OK';
        /** @var Result */
        $result = $this->scan($file);

        if ($result->isInfected()) {
            $infected = $result->getInfected();

            $stats = "{$infected[$file]} FOUND";
        }

        return array('file' => $file, 'stats' => $stats);
    }
}
