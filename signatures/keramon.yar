rule digimon_keramon
{

    meta:
        description = "Detects rookie level virus digimon, keramon"
        author = "Toei Animation"
        date = "2000-03-04"
        hash = "2e303c5557e8621a07d4910353890d6e"
        
    strings:
        $move1 = "Bug Blaster"
        $move2 = "Network Flapping"
        $text3 = "100mbps"
	$text4 = "ケラモン"

    condition:
        $move1 or $move2 or text3 or text4
}
