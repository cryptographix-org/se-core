import { ByteArray } from 'sim-core';

import { CommandAPDU } from '../base/command-apdu';
import { ResponseAPDU } from '../base/response-apdu';

export interface JSIMCard
{
  isPowered: boolean;

  powerOn(): Promise<ByteArray>;
  powerOff(): Promise<boolean>;
  reset(): Promise<ByteArray>;

  exchangeAPDU( commandAPDU: CommandAPDU ): Promise<ResponseAPDU>;
}
