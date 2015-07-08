import { ISO7816 } from '../../iso7816/ISO7816';
import { ByteString, HEX, ByteBuffer, TLV, Crypto, Key } from '../../se-core/gpscript/gpscript-package';

export class CardApplication
{
  onAPDUResponse;

  constructor( onAPDUResponse )
  {
    this.onAPDUResponse = onAPDUResponse;
  }

  selectApplication( bP1, bP2, sAID )
  {
    return { sw: 0x9000, data: null };
  }

  deselectApplication()
  {
    // no return { sw: 0x9000, data: null };
  }

  executeAPDUCommand( bCLA, bINS, bP1, bP2, commandData, wLe )
  {
    return { sw: 0x6D00, data: null };
  }
}
