import { ISO7816 } from '../base/ISO7816';
import { CommandAPDU } from '../base/command-apdu';
import { ResponseAPDU } from '../base/response-apdu';

export class JSIMApplet
{
  selectApplication( commandAPDU: CommandAPDU ): Promise<ResponseAPDU>
  {
    return new Promise<ResponseAPDU>( (resolve, reject ) => {
      return new ResponseAPDU( { sw: 0x9000, data: null } );
    });
  }

  deselectApplication()
  {
  }

  executeAPDU( commandAPDU: CommandAPDU ): Promise<ResponseAPDU>
  {
    return new Promise<ResponseAPDU>( (resolve, reject ) => {
      return new ResponseAPDU( { sw: 0x6D00, data: null } );
    });
  }
}
