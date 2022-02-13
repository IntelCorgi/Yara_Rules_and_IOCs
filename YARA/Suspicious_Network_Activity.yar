rule contacts_CDN {
    meta:
        author = "IntelCorgi"
        date = "02/13/2022"
        description = "Check if suspicious file reaches out to a CDN to grab a payload"
    strings:
        $discord = "https://cdn.discordapp.com/attachments" ascii wide
        $onedrive = "" ascii wide
    condition:
        any of them
}
