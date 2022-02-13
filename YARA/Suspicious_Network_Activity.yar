rule contacts_CDN {
    meta:
        author = "IntelCorgi"
        date = "02/13/2022"
        description = "Check if suspicious file reaches out to a CDN to grab a payload"
    strings:
        $discord = "cdn.discordapp.com/attachments/" ascii wide
        $onedrive = "onedrive.live.com/" ascii wide
        $privatlab0 = "privatlab.com/s/s/" ascii wide
        $privatlab1 = "privatlab.com/s/v/" ascii wide
        $transfer = "transfer.sh/get/" ascii wide
        $anonfiles = "anonfiles.com" ascii wide
        $sendspace = "sendspace.com/file/" ascii wide
        $fex = "fex.net/get/" ascii wide
    condition:
        any of them
}
