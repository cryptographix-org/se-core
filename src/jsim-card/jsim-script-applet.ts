import { ISO7816 } from '../base/ISO7816';
import { CommandAPDU } from '../base/command-apdu';
import { ResponseAPDU } from '../base/response-apdu';

export class JSIMScriptApplet
{
  selectApplication( commandAPDU: CommandAPDU ): Promise<ResponseAPDU>
  {
    return new Promise<ResponseAPDU>( (resolve, reject ) => {
      resolve( new ResponseAPDU( { sw: 0x9000, data: null } ) );
    });
  }

  deselectApplication()
  {
  }

  executeAPDU( commandAPDU: CommandAPDU ): Promise<ResponseAPDU>
  {
    return new Promise<ResponseAPDU>( (resolve, reject ) => {
      resolve( new ResponseAPDU( { sw: 0x6D00, data: null } ) );
    });
  }
}
