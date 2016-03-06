var setZeroPrimitives =
{
  0x01: {
    name: "CHECK_CASE",
    proc: function() { /*
  	  var expectedISO= popByte();

  	  if (expectedISO< 1 || expectedISO> 4)
  	    SetCCRFlag(Zflag, false);
  	  else
  	    SetCCRFlag(Zflag, CheckISOCase(expectedISOCase));
    */}
  },
  0x02: {
    name: "RESET_WWT",
    proc: function() { /*
      sendWaitRequest();
    */}
  },
  0x05: {
    name: "LOAD_CCR",
    proc: function() { /*
      pushByte(CCR());
    */}
  },
  0x06: {
    name: "STORE_CCR",
    proc: function() { /*
      CCR() = popByte();
    */}
  },
  0x07: {
    name: "SET_ATR_FILE_RECORD",
    proc: function() { /*
      var addr = getWord(dynamicTop-2);
      var len = getByte(addr);

      MELApplication *a = state.application;
      if (a.ATRFileRecordSize)
        delete []a.ATRFileRecord;

      a.ATRFileRecordSize = len;

      if (len)
      {
        a.ATRFileRecord = new var[len];
        read(addr, len, a.ATRFileRecord);
      }
      DT(-2);
      pushByte(len);
    */}
  },
  0x08: {
    name: "SET_ATR_HISTORICAL_CHARACTERS",
    proc: function() { /*
      var addr = getWord(dynamicTop-2);
      var len = getByte(addr);
      var written;
      var okay = setATRHistoricalCharacters(len, addr+1, written);

      DT(-2);
      pushByte(written);
      SetCCRFlag(Cflag, written < len);
      SetCCRFlag(Zflag, !okay);
    */}
  },
  0x09: {
    name: "GET_MEMORY_RELIABILITY",
    proc: function() { /*
      SetCCRFlag(Cflag, false);
      SetCCRFlag(Zflag, false);
    */}
  },
  0xa: {
    name: "LOOKUP",
    proc: function() { /*
      var value = getByte(dynamicTop-3);
      var arrAddr = getWord(dynamicTop-2);

      DT(-2);
      SetCCRFlag(Zflag, false);

      var arrlen = getByte(arrAddr);
      for (var i=0;i<arrlen;i++)
        if (getByte(arrAddr+i+1) == value)
        {
          setByte(dynamicTop-1, (var)i);
          SetCCRFlag(Zflag, true);
          i = arrlen;
        }
    */}
  },
  0xb: {
    name: "MEMORY_COMPARE",
    proc: function() { /*
      var len = getWord(dynamicTop-6);
      var op1 = getWord(dynamicTop-4);
      var op2 = getWord(dynamicTop-2);

      blockCompare(op1, op2, len);
      DT(-6);
    */}
  },
  0xc: {
    name: "MEMORY_COPY",
    proc: function() { /*
      var num = getWord(dynamicTop-6);
      var dst = getWord(dynamicTop-4);
      var src = getWord(dynamicTop-2);

      copy(dst, src, num);
      DT(-6);
    */}
  },
  0xd: {
    name: "QUERY_INTERFACE_TYPE",
    proc: function() { /*
      SetCCRFlag(Zflag, false); // contact
    */}
  },
  0x10: {
    name: "CONTROL_AUTO_RESET_WWT",
    proc: function() { /*
      // Doesn't do anything
      DT(-2);
    */}
  },
  0x11: {
    name: "SET_FCI_FILE_RECORD",
    proc: function() { /*
      var addr = getWord(dynamicTop-2);
      var len = getByte(addr);

      MELApplication *a = state.application;

      if (a.FCIRecordSize)
        delete []a.FCIRecord;

      a.FCIRecordSize = len;
      a.FCIRecord = new var[len];
      read(addr + 1, len, a.FCIRecord);
      DT(-2);
      pushByte(len);
    */}
  },
  0x80: {
    name: "DELEGATE",
    proc: function() { /*
      // rollback and turn off transaction protection
      var m = state.application.staticData;
      if (m.on)
      {
        m.discard();
        m.on = false;
      }

      var AIDAddr = getWord(dynamicTop-2);
      DT(-2);

      var AIDlen = getByte(AIDAddr);
      if (AIDlen < 1 || AIDlen > 16)
        setWord(PT()+SW1, 0x6a83);
      else
      {
        var AID = new var[AIDlen];

        read(AIDAddr+1, AIDlen, AID);
        if (!delegateApplication(AIDlen, AID))
          setWord(PT()+SW1, 0x6a83);
      }
    */}
  },
  0x81: {
    name: "RESET_SESSION_DATA",
    proc: function() { /*
      if (state.application.isShellApp)
        ResetSessionData();
    */}
  },
  0x82: {
    name: "CHECKSUM",
    proc: function() { /*
      var length = getWord(dynamicTop-4);
      var addr = getWord(dynamicTop-2);
      var checksum[4] = { 0x5a, 0xa5, 0x5a, 0xa5 };

      var m = state.application.staticData;
      var accountForTransactionProtection = (addr >= m.start() && addr <= m.start() + m.size() && m.on);

      for (var j=0; j < length; j++)
      {
        if (accountForTransactionProtection)
          checksum[0] += (var)m.readPendingByteMemory(addr+j);
        else
          checksum[0] += (var)getByte(addr + j);

        checksum[1] += checksum[0];
        checksum[2] += checksum[1];
        checksum[3] += checksum[2];
      }
      write(dynamicTop-4, 4, checksum);
    */}
  },
  0x83: {
    name: "CALL_CODELET",
    proc: function() { /*
      var codeletId = getWord(dynamicTop-4);
      var codeaddr = getWord(dynamicTop-2);

      DT(-4);
      callCodelet(codeletId, codeaddr);
    */}
  },
  0x84: {
    name: "QUERY_CODELET",
    proc: function() { /*
      var codeletId = getWord(dynamicTop-2);

      SetCCRFlag(Zflag, queryCodelet(codeletId));
      DT(-2);
    */}
  },
  0xc1: {
    name: "DES_ECB_ENCIPHER",
    proc: function() { /*
      var *key = dump(getWord(dynamicTop-0x6),8);
      var plaintextAddr = getWord(dynamicTop-0x4);
      var *ciphertext = dump(getWord(dynamicTop-0x2),8);
      var plaintext[8];

      mth_des(DES_DECRYPT, key, ciphertext, plaintext);
      write(plaintextAddr, 8, plaintext);
      DT(-6);
    */}
  },
  0xc2: {
    name: "MODULAR_MULTIPLICATION",
    proc: function() { /*
      var modlen = getWord(dynamicTop-8);
      const var *lhs = dump(getWord(dynamicTop-6), modlen);
      const var *rhs = dump(getWord(dynamicTop-4), modlen);
      const var *mod = dump(getWord(dynamicTop-2), modlen);
      var *res = new var[modlen];
      mth_mod_mult(lhs, modlen, rhs, modlen, mod, modlen, res);
      write(getWord(dynamicTop-6), modlen, res);
      DT(-8);
    */}
  },
  0xc3: {
    name: "MODULAR_REDUCTION",
    proc: function() { /*
      var oplen = getWord(dynamicTop-8);
      var modlen = getWord(dynamicTop-6);
      const var *op = dump(getWord(dynamicTop-4), oplen);
      const var *mod = dump(getWord(dynamicTop-2), oplen);
      var *res = new var[oplen];
      mth_mod_red(op, oplen, mod, modlen, res);
      write(getWord(dynamicTop-4), oplen, res);
      DT(-8);
      delete []res;
    */}
  },
  0xc4: {
    name: "GET_RANDOM_NUMBER",
    proc: function() { /*
      var rand[8];
      randdata(rand, 8);
      DT(8);
      write(dynamicTop-8, 8, rand);
    */}
  },
  0xc5: {
    name: "DES_ECB_DECIPHER",
    proc: function() { /*
      var *key = dump(getWord(dynamicTop-0x6),8);
      var cipherAddr = getWord(dynamicTop-0x4);
      var *plaintext = dump(getWord(dynamicTop-0x2),8);
      var ciphertext[8];

      mth_des(DES_ENCRYPT, key, plaintext, ciphertext);
      write(cipherAddr, 8, ciphertext);
      DT(-6);
    */}
  },
  0xc6: {
    name: "GENERATE_DES_CBC_SIGNATURE",
    proc: function() { /*
      var plainTextLength = getWord(dynamicTop-0xa);
      var IVaddr = getWord(dynamicTop-0x8);
      var *key = dump(getWord(dynamicTop-0x6), 8);
      var signatureAddr = getWord(dynamicTop-0x4);
      var *plainText = dump(getWord(dynamicTop-0x2), plainTextLength);
      var signature[8];

      read(IVaddr, 8, signature);
      while (plainTextLength >= 8)
      {
        for (var i=0;i<8;i++)
          signature[i] ^= plainText[i];

        var encryptedSignature[8];

        mth_des(DES_ENCRYPT, key, signature, encryptedSignature);
        memcpy(signature, encryptedSignature, 8);
        plainTextLength -= 8;
        plainText += 8;
      }
      write(signatureAddr, 8, signature);
      DT(-10);
    */}
  },
  0xc7: {
    name: "GENERATE_TRIPLE_DES_CBC_SIGNATURE",
    proc: function() { /*
      int plainTextLength = getWord(dynamicTop-0xa);
      var IVaddr = getWord(dynamicTop-0x8);
      var key1 = dump(getWord(dynamicTop-0x6), 16);
      var key2 = key1 + 8;
      var signatureAddr = getWord(dynamicTop-0x4);
      var plainText = dump(getWord(dynamicTop-0x2), plainTextLength);
      var signature[8];

      read(IVaddr, 8, signature);
      while (plainTextLength > 0)
      {
        for (var i=0;i<8;i++)
          signature[i] ^= plainText[i];

        var encryptedSignature[8];

        mth_des(DES_ENCRYPT, key1, signature, encryptedSignature);
        mth_des(DES_DECRYPT, key2, encryptedSignature, signature);
        mth_des(DES_ENCRYPT, key1, signature, encryptedSignature);
        memcpy(signature, encryptedSignature, 8);
        plainTextLength -= 8;
        plainText += 8;
      }
      write(signatureAddr, 8, signature);
      DT(-10);
    */}
  },
  0xc8: {
    name: "MODULAR_EXPONENTIATION",
    proc: function() { /*
      var explen = getWord(dynamicTop-0xc);
      var modlen = getWord(dynamicTop-0xa);
      var exponent = dump(getWord(dynamicTop-0x8), explen);
      var mod = dump(getWord(dynamicTop-0x6), modlen);
      var base = dump(getWord(dynamicTop-0x4), modlen);
      var resAddr = getWord(dynamicTop-0x2);
      var res = new var[modlen];

      mth_mod_exp(base, modlen, exponent, explen, mod, modlen, res);
      write(resAddr, modlen, res);
      DT(-12);

      delete []res;
    */}
  },
  0xc9: {
    name: "MODULAR_EXPONENTIATION_CRT",
    proc: function() { /*
      var modulus_len = getWord(dynamicTop-10);
      var dpdq = dump(getWord(dynamicTop-8), modulus_len);
      var pqu  = dump(getWord(dynamicTop-6), modulus_len * 3 / 2);
      var base = dump(getWord(dynamicTop-4), modulus_len);
      var outAddr = getWord(dynamicTop-2);
      var res = new var[modulus_len];

      mth_mod_exp_crt(modulus_len, dpdq, pqu, base, res);
      write(outAddr, modulus_len, res);
      DT(-10);
      delete[] res;
    */}
  },
  0xca: {
    name: "SHA1",
    proc: function() { /*
      var plaintextLength = getWord(dynamicTop-0x6);
      var hashDigestAddr = getWord(dynamicTop-0x4);
      var plaintext = dump(getWord(dynamicTop-0x2), plaintextLength);
      var long hashDigest[5]; // 20 byte hash

      mth_sha_init(hashDigest);

      while (plaintextLength > 64)
      {
        mth_sha_update(hashDigest, (var *)plaintext);
        plaintext += 64;
        plaintextLength -= 64;
      }

      mth_sha_final(hashDigest, (var *)plaintext, plaintextLength);

      for (int i=0;i<5;i++)
        writeNumber(hashDigestAddr+(i*4), 4, hashDigest[i]);

      DT(-6);
    */}
  },
  0xcc: {
    name: "GENERATE_RANDOM_PRIME",
    proc: function() { /*
      var gcdFlag = getByte(dynamicTop-13);
      var conf = getWord(dynamicTop-12);
      var timeout = getWord(dynamicTop-10);
      var rgExp = getWord(dynamicTop-8);
      const var *minLoc = dump(getWord(dynamicTop-6), 4);
      const var *maxLoc = dump(getWord(dynamicTop-4), 4);
      var resAddr = getWord(dynamicTop-0x2);
      if ((rgExp < 5) || (rgExp > 256))
      {
        Abend("rgExp parameter out of range");
      }
      else
      {
        static const vlong one(1);
        static const vlong three(3);
        std::vector<var> candidate(rgExp);
        for (;;)
        {
          std::generate(candidate.begin(), candidate.end(), rand);
          if (std::lexicographical_compare(
                candidate.begin(), candidate.end(),
                minLoc, minLoc + 4))
            continue;
          if (std::lexicographical_compare(
                maxLoc, maxLoc + 4,
                candidate.begin(), candidate.end()))
            continue;
          vlong vlong_candidate(candidate.size(), &candidate[0]);
          if (0x80 == gcdFlag)
          {
            if (one != gcd(three, vlong_candidate))
              continue;
          }
          if (!is_probable_prime(vlong_candidate))
            continue;

          break;
        }
        write(resAddr, rgExp, &candidate[0]);
        DT(-13);
      }
    */}
  },
  0xcd: {
    name: "SEED_ECB_DECIPHER",
    proc: function() { /*
      static const var block_size = 16;

      const var *key = dump(getWord(dynamicTop-6), block_size);
      var resAddr = getWord(dynamicTop-0x4);
      const var *plaintext = dump(getWord(dynamicTop-2), block_size);

      var buffer[block_size];
      memcpy(buffer, key, block_size);
      DWORD round_key[2 * block_size];
      SeedEncRoundKey(round_key, buffer);
      memcpy(buffer, plaintext, block_size);
      SeedDecrypt(buffer, round_key);

      write(resAddr, block_size, buffer);
      DT(-6);
    */}
  },
  0xce: {
    name: "SEED_ECB_ENCIPHER",
    proc: function() { /*
      static const var block_size = 16;

      const var *key = dump(getWord(dynamicTop-6), block_size);
      var resAddr = getWord(dynamicTop-0x4);
      const var *plaintext = dump(getWord(dynamicTop-2), block_size);

      var buffer[block_size];
      memcpy(buffer, key, block_size);
      DWORD round_key[2 * block_size];
      SeedEncRoundKey(round_key, buffer);
      memcpy(buffer, plaintext, block_size);
      SeedEncrypt(buffer, round_key);

      write(resAddr, block_size, buffer);
      DT(-6);
    */}
  }
};

var setOnePrimitives =
{
  0x00: {
    name: "QUERY0",
    proc: function() { /*
      i = prim0.find(arg1);
      SetCCRFlag(Zflag, i != prim0.end());
    */}
  },
  0x01: {
    name: "QUERY1",
    proc: function() { /*
      i = prim1.find(arg1);
      SetCCRFlag(Zflag, i != prim1.end());
    */}
  },
  0x02: {
    name: "QUERY2",
    proc: function() { /*
      i = prim2.find(arg1);
      SetCCRFlag(Zflag, i != prim2.end());
    */}
  },
  0x03: {
    name: "QUERY3",
    proc: function() { /*
      i = prim3.find(arg1);
      SetCCRFlag(Zflag, i != prim3.end());
    */}
  },
  0x08: {
    name: "DIVIDEN",
    proc: function() { /*
      var len = arg1;
      var *denominator = dump(dynamicTop-len, len);
      if (blockIsZero(denominator, len))
      {
        SetCCRFlag(Cflag, true);
      }
      else
      {
        const var *numerator = dump(dynamicTop-2*len, len);
        var *quotient = new var[len];
        var *remainder = new var[len];
        mth_div(numerator, denominator, len, quotient, remainder);
        write(dynamicTop-2*len, len, quotient);
        write(dynamicTop-len, len, remainder);
        SetCCRFlag(Cflag, false);
        SetCCRFlag(Zflag, blockIsZero(quotient,len));
        delete []quotient;
        delete []remainder;
      }
    */}
  },
  0x09: {
    name: "GET_DIR_FILE_RECORD",
    proc: function() { /*
      // Same as below
      MULTOS.Primitives.setOnePrimitives[ 0x0a ].proc();
    */}
  },
  0x0a: {
    name: "GET_FILE_CONTROL_INFORMATION",
    proc: function() { /*
      var len = arg1;
      var addr = getWord(dynamicTop-3);
      var recordNumber = getByte(dynamicTop-1);
      var okay;
      var *data;
      var datalen;
      if (prim == GET_DIR_FILE_RECORD)
        okay = getDirFileRecord(recordNumber-1, &datalen, &data);
      else
        okay = getFCI(recordNumber-1, &datalen, &data);
      if (okay)
        {
          var copied = len < datalen ? len : datalen;
          if (copied)
            write(addr, copied, data);
          pushByte(copied);
          SetCCRFlag(Cflag, (copied < len));
          SetCCRFlag(Zflag, 0);
        }
      else
        {
          pushByte(0);
          SetCCRFlag(Cflag, 1);
          SetCCRFlag(Zflag, 1);
        }
    */}
  },
  0x0b: {
    name: "GET_MANUFACTURER_DATA",
    proc: function() { /*
      var addr = getWord(dynamicTop-2);
      DT(-1);
      var manufacturer[256];
      var len = getManufacturerData(manufacturer);
      len = arg1 < len ? arg1 : len;
      if (len)
        write(addr, len, manufacturer);
      setByte(dynamicTop-1, (var)len);
    */}
  },
  0x0c: {
    name: "GET_MULTOS_DATA",
    proc: function() { /*
      var addr = getWord(dynamicTop-2);
      DT(-1);
      var MULTOSData[256];
      var len = getMULTOSData(MULTOSData);
      if (len)
        len = arg1 < len ? arg1 : len;
      write(addr, len, MULTOSData);
      setByte(dynamicTop-1, (var)len);
    */}
  },
  0x0d: {
    name: "GET_PURSE_TYPE",
    proc: function() { /*
      Abend("primitive not supported");
    */}
  },
  0x0e: {
    name: "MEMORY_COPY_FIXED_LENGTH",
    proc: function() { /*
      var dst = getWord(dynamicTop-4);
      var src = getWord(dynamicTop-2);

      copy(dst, src, arg1);
      DT(-4);
    */}
  },
  0x0f: {
    name: "MEMORY_COMPARE_FIXED_LENGTH",
    proc: function() { /*
      var op1 = getWord(dynamicTop-4);
      var op2 = getWord(dynamicTop-2);
      blockCompare(op1, op2, arg1);
      DT(-4);
    */}
  },
  0x10: {
    name: "MULTIPLYN",
    proc: function() { /*
      var len = arg1;
      const var *op1 = dump(dynamicTop-2*len, len);
      const var *op2 = dump(dynamicTop-len, len);
      var *res = new var[len*2];
      mth_mul(op1, op2, len, res);
      write(dynamicTop-2*len, len*2, res);
      SetCCRFlag(Zflag, blockIsZero(res,len*2));
      delete []res;
    */}
  },
  0x80: {
    name: "SET_TRANSACTION_PROTECTION",
    proc: function() { /*
      var m = state.application.staticData;
      if (m.on)
        {
          if (arg1 & 1)
            m.commit();
          else
            m.discard();
        }
      if (arg1 & 2)
        m.on = true;
      else
        m.on = false;
    */}
  },
  0x81: {
    name: "GET_DELEGATOR_AID",
    proc: function() { /*
      var AIDAddr = getWord(dynamicTop-2);
      DT(-2);
      MELExecutionState *e = getDelegatorState();
      if (e)
        {
          var len;
          if ( arg1 < e.application.AIDlength)
            {
              len = arg1;
              SetCCRFlag(Cflag, true);
            }
          else
            {
              len =  e.application.AIDlength;
              SetCCRFlag(Cflag, false);
            }
          setByte(AIDAddr, (var)len);
          AIDAddr++;
          for (var i=0; i < len; i++)
            setByte(AIDAddr+i, e.application.AID[i]);
          SetCCRFlag(Zflag, false);
        }
      else
        SetCCRFlag(Zflag, true);
    */}
  },
  0xc4: {
    name: "GENERATE_ASYMMETRIC_HASH",
    proc: function() { /*
      const var *iv;
      var plain_len;
      var digestOutAddr;
      const var *plain;
      MELKey* ahashKey;
      int dtval;
      std::auto_ptr<SimpleMELKeyWrapper> smkw;
      var hcl = 16;

      switch (arg1)
      {
        case 0:
          iv = 0;
          plain_len = getWord(dynamicTop-6);
          digestOutAddr = getWord(dynamicTop-4);
          plain = dump(getWord(dynamicTop-2), plain_len);
          ahashKey = getAHashKey();
          dtval = -6;
          break;

        case 1:
          iv = dump(getWord(dynamicTop-8), 16);
          plain_len = getWord(dynamicTop-6);
          digestOutAddr = getWord(dynamicTop-4);
          plain = dump(getWord(dynamicTop-2), plain_len);
          ahashKey = getAHashKey();
          dtval = -6;
          break;

        case 2:
          iv = 0;
          plain_len = getWord(dynamicTop-10);
          digestOutAddr = getWord(dynamicTop-8);
          plain = dump(getWord(dynamicTop-6), plain_len);
          var modulus_len = getWord(dynamicTop-4);
          var modulus = dump(getWord(dynamicTop-2), modulus_len);
          smkw = std::auto_ptr<SimpleMELKeyWrapper>(new SimpleMELKeyWrapper(modulus_len, modulus));
          ahashKey = smkw.get();
          dtval = -10;
          break;

        case 3:
          iv = dump(getWord(dynamicTop-12), 16);
          plain_len = getWord(dynamicTop-10);
          digestOutAddr = getWord(dynamicTop-8);
          plain = dump(getWord(dynamicTop-6), plain_len);
          var modulus_len = getWord(dynamicTop-4);
          const var* modulus = dump(getWord(dynamicTop-2), modulus_len);
          smkw = std::auto_ptr<SimpleMELKeyWrapper>(new SimpleMELKeyWrapper(modulus_len, modulus));
          ahashKey = smkw.get();
          dtval = -12;
          break;

        case 4:
          iv = 0;
          plain_len = getWord(dynamicTop-12);
          digestOutAddr = getWord(dynamicTop-10);
          plain = dump(getWord(dynamicTop-8), plain_len);
          var modulus_len = getWord(dynamicTop-6);
          const var* modulus = dump(getWord(dynamicTop-4), modulus_len);
          smkw = std::auto_ptr<SimpleMELKeyWrapper>(new SimpleMELKeyWrapper(modulus_len, modulus));
          ahashKey = smkw.get();
          hcl = getWord(dynamicTop-2);
          dtval = -12;
          break;

        case 5:
          hcl = getWord(dynamicTop-2);
          iv = dump(getWord(dynamicTop-14), hcl);
          plain_len = getWord(dynamicTop-12);
          digestOutAddr = getWord(dynamicTop-10);
          plain = dump(getWord(dynamicTop-8), plain_len);
          var modulus_len = getWord(dynamicTop-6);
          const var* modulus = dump(getWord(dynamicTop-4), modulus_len);
          smkw = std::auto_ptr<SimpleMELKeyWrapper>(new SimpleMELKeyWrapper(modulus_len, modulus));
          ahashKey = smkw.get();
          dtval = -14;
          break;

        default:
          Abend("bad b2 value for GenerateAsymmetricHash primitive");
          break;
      }

      std::vector<var> hash(hcl);
      AHash(ahashKey, plain_len, plain, &hash[0], iv, hcl);
      write(digestOutAddr, hcl, &hash[0]);
      DT(dtval);
    */}
  }
};

function bitManipulate(bitmap, literal, data)
{
  var modify = ((bitmap & (1<<7)) == (1<<7));
  if (bitmap & 0x7c) // bits 6-2 should be zero
    throw new Error( "Undefined arguments");

  switch (bitmap & 3)
  {
    case 3:
      data &= literal;
      break;
    case 2:
      data |= literal;
      break;
    case 1:
      data = ~(data ^ literal);
      break;
    case 0:
      data ^= literal;
      break;
  }

  //SetCCRFlag(Zflag, data==0);

  return modify; //TODO: return data
}

var setTwoPrimitives =
{
  0x01: {
    name: "BIT_MANIPULATE_BYTE",
    proc: function() { /*/*
      var b = getByte(dynamicTop-1);

      if (bitManipulate(arg1, arg2, b))
        setByte(dynamicTop-1, (var)b);
    */}
  },
  0x02: {
    name: "SHIFT_LEFT",
    proc: function() { /*
      // same as SHIFT_RIGHT
    */}
  },
  0x03: {
    name: "SHIFT_RIGHT",
    proc: function() { /*
      var len = arg1;
      var numShiftBits = arg2;
      if (!len || !numShiftBits || numShiftBits>=8*len)
        Abend("undefined shift arguments");

      var *data = new var[len];
      read(dynamicTop-len, len, data);

      if (prim == SHIFT_LEFT)
      {
        SetCCRFlag(Cflag, blockBitSet(len, data, len*8-numShiftBits));
        mth_shl(data, len, numShiftBits);
      }
      else
      {
        SetCCRFlag(Cflag, blockBitSet(len, data, numShiftBits-1));
        mth_shr(data, len, numShiftBits);
      }

      write(dynamicTop-len, len, data);
      SetCCRFlag(Zflag, blockIsZero(data,len));
      delete []data;
    */}
  },
  0x04: {
    name: "SET_SELECT_SW",
    proc: function() { /*
      setSelectSW(arg1, arg2);
    */}
  },
  0x05: {
    name: "CARD_BLOCK",
    proc: function() { /*
      Abend("primitive not supported");
    */}
  },
  0x80: {
    name: "RETURN_FROM_CODELET",
    proc: function() { /*
      returnFromCodelet(arg1, arg2);
    */}
  }
}

var setThreePrimitives =
{
  0x01: {
    name: "BIT_MANIPULATE_WORD",
    proc: function() { /*
      var w = getWord(dynamicTop-2);

      if (bitManipulate(arg1, mkWord(arg2, arg3), w))
        setWord(dynamicTop-2, w);
    */}
  },
  0x80: {
    name: "CALL_EXTENSION_PRIMITIVE0",
    proc: function() { /*
      Abend("primitive not supported");
    */}
  },
  0x81: {
    name: "CALL_EXTENSION_PRIMITIVE1",
    proc: function() { /*
      Abend("primitive not supported");
    */}
  },
  0x82: {
    name: "CALL_EXTENSION_PRIMITIVE2",
    proc: function() { /*
      Abend("primitive not supported");
    */}
  },
  0x83: {
    name: "CALL_EXTENSION_PRIMITIVE3",
    proc: function() { /*
      Abend("primitive not supported");
    */}
  },
  0x84: {
    name: "CALL_EXTENSION_PRIMITIVE4",
    proc: function() { /*
      Abend("primitive not supported");
    */}
  },
  0x85: {
    name: "CALL_EXTENSION_PRIMITIVE5",
    proc: function() { /*
      Abend("primitive not supported");
    */}
  },
  0x86: {
    name: "CALL_EXTENSION_PRIMITIVE6",
    proc: function() { /*
      Abend("primitive not supported");
    */}
  }
};

var primitiveSets = [
  setZeroPrimitives,
  setOnePrimitives,
  setTwoPrimitives,
  setThreePrimitives
];

export function callPrimitive( ctx, prim, set, arg1, arg2, arg3 )
{
  var primInfo = primitiveSets[ set ][ prim ];

  if ( primInfo )
  {
    switch( set )
    {
      case 0: primInfo.proc(); break;
      case 1: primInfo.proc( arg1 ); break;
      case 2: primInfo.proc( arg1, arg2 ); break;
      case 3: primInfo.proc( arg1, arg2, arg3 ); break;
    }
  }
  else
  {
    // no prim
    throw new Error( "Primitive not Implemented" );
  }
}
