/* Rule Set ----------------------------------------------------------------- */

rule _root_Documents_crack_Adwind {
   meta:
      description = "crack - file Adwind.exe"
      author = "hk0x1"
      date = "2024-01-02"
      hash1 = "bbc572cced7c94d63a7208f4aba4ed20d1350bef153b099035a86c95c8d96d4a"
   strings:
      $s2 = "xfzzzf" fullword ascii
      $s3 = "GeUb)z6K" fullword ascii
      $s4 = "IIIIiIiIIi.classuSko" fullword ascii
      $s5 = "IiIiIIiiIi.class" fullword ascii
      $s6 = "iiiiIiIIIi.class}T" fullword ascii
      $s7 = "IiIiIIiiIi.classPK" fullword ascii
      $s8 = "iiiiIiIIIi.classPK" fullword ascii
      $s9 = "IIIIiIiIIi.classPK" fullword ascii
      $s10 = "META-INF/MANIFEST.MFPK" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "xnSyH5" fullword ascii
      $s12 = "*}+._$" fullword ascii
      $s13 = "*xt;_D" fullword ascii
      $s14 = "<o:dyE" fullword ascii
      $s15 = "K(H(JX" fullword ascii
      $s16 = "10/10/10/PK" fullword ascii
      $s17 = "o_yQa-" fullword ascii
      $s18 = "<e/jApX" fullword ascii
      $s19 = "$zxi{s(" fullword ascii
      $s20 = "sFm\"tDd(b" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 20KB and
      8 of them
}

