
/* Rule Set ----------------------------------------------------------------- */

rule _root_Documents_crack_DanaBot {
   meta:
      description = "crack - file DanaBot.exe"
      author = "hk0x1"
      date = "2024-01-03"
      hash1 = "db0d72bc7d10209f7fa354ec100d57abbb9fe2e57ce72789f5f88257c5d3ebd1"
   strings:
      $s1 = "buzuwuzaji.exe" fullword ascii
      $s2 = " Type Descriptor'" fullword ascii
      $s3 = "Povaloya juluzireyehuj\\Matafavosiy xazo janelagunevuvo yuli fepotazikokakav tuketeselogelot kakulenavik kizetudijaznHumacabuzun" wide
      $s4 = "FaKe\"k" fullword ascii
      $s5 = "Tisenewol bajizuc veyeloromas Jafuzojanufa puyova buzufovubusu" fullword wide
      $s6 = "FubigawutojodiRDahohizal xipimejusunaso seka ruwibitugiwen leju koyozada wiwusagerebis litocopowiCDopak xilizirala vijojoj zaxes" wide
      $s7 = "jjllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll" ascii
      $s8 = "jjjjjjjjjjjjjjz" fullword ascii
      $s9 = "jjjjjjjjjjjjjjj" fullword ascii
      $s10 = "lllllpf" fullword ascii
      $s11 = "jjllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll" ascii
      $s12 = "rHASh56" fullword ascii
      $s13 = "I:\\r{V" fullword ascii
      $s14 = "V:\"ogW=" fullword ascii
      $s15 = "&(U:\\hO" fullword ascii
      $s16 = "<( I:\\" fullword ascii
      $s17 = "@plusTokenAfter@4" fullword ascii
      $s18 = "Nerakeyiti facepumajuh[Tapoy cowitosaxosa nixewesefix mumo cixiyumi boyidaxic gawececutahu tupuxasejaridin jecerig" fullword wide
      $s19 = "Sllllllllllll" fullword ascii
      $s20 = "Slllllllllp" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      8 of them
}

