rule EICAR_AV_Test : unknown {
    meta:
        author = "defkit"
        date = "2026-03-28"
        version = "1.0"
        md5 = "44d88612fea8a8f36de82e1278abb02f"
        sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        severity = "low"
    strings:
        $str1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii wide nocase
    condition:
        1 of ($str*) and filesize < 10MB
}
