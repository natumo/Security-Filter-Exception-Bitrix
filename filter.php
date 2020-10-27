<?php

class SecurityFilterException{
    private $securityMask = 'path to file';
    public function addSecurityFilter()
    {

        if (CModule::IncludeModule("security")) {
            $maskList = $this->getSecurityFilterList();
            if (array_search($this->securityMask, array_column($maskList, 'MASK')) !== false) return;
            $maskList[] = array(
                "MASK" => $this->securityMask,
                "SITE_ID" => ""
            );

            CSecurityFilterMask::Update($maskList);
        }
    }

    public function removeSecurityFilter()
    {
        if (CModule::IncludeModule("security")) {
            $maskList = $this->getSecurityFilterList($this->securityMask);
            CSecurityFilterMask::Update($maskList);
        }
    }

    public function getSecurityFilterList($exception = '')
    {

        $result = array();
        $dbSecurityFilter = CSecurityFilterMask::GetList();

        while ($arSecurityFilter = $dbSecurityFilter->Fetch()) {
            if ($exception && $arSecurityFilter["FILTER_MASK"] == $exception) continue;
            $result[] = array(
                "MASK" => $arSecurityFilter["FILTER_MASK"],
                "SITE_ID" => $arSecurityFilter["SITE_ID"]
            );
        }

        return $result;
    }
}