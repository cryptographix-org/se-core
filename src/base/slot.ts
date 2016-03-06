import { ByteArray } from 'cryptographix-sim-core'; 
import { CommandAPDU } from './command-apdu';
import { ResponseAPDU } from './response-apdu';

export interface Slot
{
  isPresent: boolean;
  isPowered: boolean;

  powerOn(): Promise<ByteArray>;
  powerOff(): Promise<boolean>;
  reset(): Promise<ByteArray>;

  executeAPDU( commandAPDU: CommandAPDU ): Promise<ResponseAPDU>;
}
