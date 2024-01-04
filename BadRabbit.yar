
/* Rule Set ----------------------------------------------------------------- */

rule BadRabbit {
   meta:
      description = "crack - file BadRabbit.exe"
      author = "yarGen Rule Generator"
      date = "2024-01-04"
      hash1 = "630325cac09ac3fab908f903e3b00d0dadd5fdaa0875ed8496fcbb97a558d0da"
   strings:
      $s1 = "FlashUtil.exe" fullword wide
      $s2 = "http://rb.symcb.com/rb.crt0" fullword ascii
      $s3 = "https://d.symcb.com/rpa06" fullword ascii
      $s4 = "C:\\Windows\\infpub.dat" fullword wide
      $s5 = "(Symantec SHA256 TimeStamping Signer - G2" fullword ascii
      $s6 = "(Symantec SHA256 TimeStamping Signer - G20" fullword ascii
      $s7 = "http://rb.symcd.com0&" fullword ascii
      $s8 = "http://s.symcd.com0" fullword ascii
      $s9 = "infpub.dat" fullword wide
      $s10 = "http://rb.symcb.com/rb.crl0W" fullword ascii
      $s11 = "        <requestedExecutionLevel level=\"highestAvailable\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s12 = ",Symantec Class 3 SHA256 Code Signing CA - G20" fullword ascii
      $s13 = ",Symantec Class 3 SHA256 Code Signing CA - G2" fullword ascii
      $s14 = "%ws C:\\Windows\\%ws,#1 %ws" fullword wide
      $s15 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s16 = " 1996-2017 Adobe Systems Incorporated" fullword wide
      $s17 = "DDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPA" ascii
      $s18 = " inflate 1.2.8 Copyright 1995-2013 Mark Adler " fullword ascii
      $s19 = "\\lERi!" fullword ascii
      $s20 = "%P%</vb" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

