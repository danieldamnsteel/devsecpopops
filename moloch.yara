rule demon_moloch
{

    meta:
        description = "Detects Moloch the Corruptor"
        author = "Cortonan Monks"
        date = "1418-04-28"
        hash = "6cbfeb7526de65eb2e3c848acac05da1e885636d17c1c45c62ad37e44cd84f99"
        
    strings:
        $text1 = "All I want is your love"
        $text2 = "Circle of Kayless"
        $text3 = "g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d"

    condition:
        $text1 or $text2 or text3
}
