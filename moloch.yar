rule demon_moloch
{

    meta:
        description = "Detects Moloch the Corruptor"
        author = "Cortonan Monks"
        date = "1418-04-28"
        hash = "9e314e368168bcf961856d72914247fc"
        
    strings:
        $text1 = "All I want is your love"
        $text2 = "Circle of Kayless"
        $text3 = "Do you love me?"

    condition:
        $text1 or $text2 or text3
}
