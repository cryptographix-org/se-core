import { ISO7816 } from '../iso7816/ISO7816';
import { CommandAPDU } from '../iso7816/command-apdu';
import { ResponseAPDU } from '../iso7816/response-apdu';

export class JSIMScriptApplet
{
  selectApplication( commandAPDU: CommandAPDU ): Promise<ResponseAPDU>
  {
    return Promise.resolve<ResponseAPDU>( new ResponseAPDU( { sw: 0x9000 } ) );
  }

  deselectApplication()
  {
  }

  executeAPDU( commandAPDU: CommandAPDU ): Promise<ResponseAPDU>
  {
    return Promise.resolve<ResponseAPDU>( new ResponseAPDU( { sw: 0x6D00 } ) );
  }
}
