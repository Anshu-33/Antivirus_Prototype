rule EICAR_Test_File
{
    meta:
        description = "Detects the EICAR antivirus test file"
        author = "YourName"
        reference = "https://www.eicar.org/"
        date = "2025-04-19"
        test_file = true

    strings:
        $eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar_string
}
