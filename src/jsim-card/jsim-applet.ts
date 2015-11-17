import { ISO7816 } from '../iso7816/ISO7816';
import { CommandAPDU } from '../iso7816/command-apdu';
import { ResponseAPDU } from '../iso7816/response-apdu';

export class JSIMApplet
{
  onAPDUResponse;

  constructor( onAPDUResponse )
  {
    this.onAPDUResponse = onAPDUResponse;
  }

  selectApplication( bP1, bP2, sAID ): ResponseAPDU
  {
    return new ResponseAPDU( { sw: 0x9000, data: null } );
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
