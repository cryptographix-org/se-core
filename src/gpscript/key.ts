import { ByteString } from './byte-string';

export class Key
{
  _type: number;
  _size: number;
  _componentArray: ByteString[];

  constructor()
  {
    this._type = 0;
    this._size = -1;
    this._componentArray = [];
  }

  setType( keyType: number )
  {
    this._type = keyType;
  }

  getType(): number
  {
    return this._type;
  }

  setSize( size: number )
  {
    this._size = size;
  }

  getSize(): number
  {
    return this._size;
  }

  setComponent( comp: number, value: ByteString )
  {
    this._componentArray[ comp ] = value;
  }

  getComponent( comp: number ): ByteString
  {
    return this._componentArray[ comp ];
  }


  static SECRET = 1;
  static PRIVATE = 2;
  static PUBLIC = 3;

  static DES = 1;
  static AES = 2;
  static MODULUS = 3;
  static EXPONENT = 4;
  static CRT_P = 5;
  static CRT_Q = 6;
  static CRT_DP1 = 7;
  static CRT_DQ1 = 8;
  static CRT_PQ = 9;
}
