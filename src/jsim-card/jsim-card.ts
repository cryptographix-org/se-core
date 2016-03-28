import { ByteArray } from 'cryptographix-sim-core';

import { CommandAPDU } from '../iso7816/command-apdu';
import { ResponseAPDU } from '../iso7816/response-apdu';

export interface JSIMCard
{
  isPowered: boolean;

  powerOn(): Promise<ByteArray>;
  powerOff(): Promise<ByteArray>;
  reset(): Promise<ByteArray>;

  exchangeAPDU( commandAPDU: CommandAPDU ): Promise<ResponseAPDU>;
}
