rule contacts_fileshare_or_CDN {
    meta:
        author = "IntelCorgi"
        date = "02/13/2022"
        description = "Check if suspicious file reaches out to a fileshare/cdn to grab a payload"
    strings:
        $a1 = "cdn.discordapp.com/attachments/" ascii wide
        $a2 = "onedrive.live.com/" ascii wide
        $a3 = "privatlab.com/s/s/" ascii wide
        $a4 = "privatlab.com/s/v/" ascii wide
        $a5 = "transfer.sh/get/" ascii wide
        $a6 = "anonfiles.com" ascii wide
        $a7 = "sendspace.com/file/" ascii wide
        $a8 = "fex.net/get/" ascii wide
        $a9 = "mediafire.com/file/" ascii wide //suggested by @Ledtech3
    condition:
        any of $a
}
