#include "stdafx.h"

/**
 * @fn コンストラクタ
 * @param _inputFileName 入力ファイル名
 * @param _outputFileName 出力ファイル名
 */
Encrypt::Encrypt(char* _inputFileName, char* _outputFileName, int _keyLength)
    : mKeyLength(_keyLength)             //鍵の長さ 4,6,8(128,192,256 bit)
    , mRound(mKeyLength + 6)    //ラウンド数 10,12,14
    , mIfs(nullptr)
    , mOfs(nullptr)
{
    //入力ファイルを開く処理
    bool practicable = OpenInputFile(_inputFileName);

    //書き込むための出力ファイルを生成
    mOfs = new ofstream(_inputFileName, ios::app | ios::binary);

    //共通鍵の長さを指定してコピー
    memcpy(mKey, mKeys, mKeyLength * 4);

    //暗号化するための鍵の準備
    KeyExpansion(mKey);

    //入力ファイルが開かれたら書き込み処理を行う
    if (practicable)
    {
        //初回の1ブロック分の暗号化データを書き込み
        InitWritingEncryptData();
        //EOFまで暗号化したデータを書き込み
        WritingEncryptData();

        cout << "暗号化成功" << endl;
    }
    //入力ファイルが開けなかったら書き込み処理を行わない
    else
    {
        cout << "暗号化失敗" << endl;
        return;
    }

    practicable = false;
}

/**
 * @fn デストラクタ
 */
Encrypt::~Encrypt()
{
    delete mIfs;
    delete mOfs;
}

/**
 * @fn 入力ファイルを開く
 * @param _inputFileName 入力ファイル名
 * @return true : 開けた, false : 開けなかった
 */
bool Encrypt::OpenInputFile(char* _inputFileName)
{
    //ファイル名からバイナリファイルで読み込む
    mIfs = new ifstream(_inputFileName, ios::binary);

    //ファイルが存在するかチェック
    bool fileCheck = mIfs->is_open();

    //ファイルが開けなかったらfalseを返す
    if (!fileCheck)
    {
        cout << "入力ファイルが開けませんでした" << endl;
        return false;
    }

    //ファイルが開けたらtrueを返す
    cout << "入力ファイルを開けました" << endl;
    return true;
}

/**
 * @fn 初回の1ブロック分の暗号化データを書き込み
 */
void Encrypt::InitWritingEncryptData()
{
    //初期化ベクトルの中身を全て"R" = 0x52にする
    memset(mInitialData, 'R', NBb);

    //最初の1ブロックをデータ読込
    mIfs->read((char*)mData, NBb);

    //暗号ブロックに読み込んだデータをnバイト分XORして代入(n = バイト数)
    for (int i = 0; i < NB; i++)
    {
        mEncryptBlock[i] = mData[i] ^ mInitialData[i];
    }

    //最初の1ブロックを暗号化
    Cipher(mEncryptBlock);

    //暗号化した最初の1ブロックを書き込み
    mOfs->write((char*)mEncryptBlock, NBb);

    //1つ前の暗号ブロックに暗号化されているブロックを格納
    memcpy(mEncryptBlockPre, mEncryptBlock, NBb);
}

/**
 * @fn EOFまで暗号化したデータを書き込み
 */
void Encrypt::WritingEncryptData()
{
    while (true)
    {
        //1ブロック分データ読込
        mIfs->read((char*)mData, NBb);

        //データがなかった場合終了する。
        if (mIfs->eof())
        {
            break;
        }

        //ブロック長ごとに処理
        //暗号ブロックに読み込んだデータをnバイト分XORして代入(n = バイト数)
        for (int i = 0; i < NB; i++)
        {
            mEncryptBlock[i] = mData[i] ^ mEncryptBlockPre[i];
        }

        //1ブロック分暗号化
        Cipher(mEncryptBlock);

        //暗号化した1ブロックを書き込み
        mOfs->write((char*)mEncryptBlock, NBb);

        //1つ前の暗号ブロックに暗号化されているブロックを格納
        memcpy(mEncryptBlockPre, mEncryptBlock, NBb);

        cout << "writing" << endl;
    }
}

/**
 * @fn AESによる暗号化
 * @param _data 入力ファイルを読み込んだデータ
 */
int Encrypt::Cipher(int* _data)
{
    int i;

    AddRoundKey(_data, 0);

    for (i = 1; i < mRound; i++)
    {
        SubBytes(_data);
        ShiftRows(_data);
        MixColumns(_data);
        AddRoundKey(_data, i);
    }

    SubBytes(_data);
    ShiftRows(_data);
    AddRoundKey(_data, i);

    return i;
}

/**
 * @fn 各マスに分けられた1byte長のマスの内部で換字表(フォワードSボックス)を用いてbit置換を行う
 * @param _data 入力ファイルを読み込んだデータ
 */
void Encrypt::SubBytes(int* _data)
{
    int i, j;
    unsigned char* cb = (unsigned char*)_data;

    for (i = 0; i < NBb; i += 4)
    {
        for (j = 0; j < 4; j++)
        {
            cb[i + j] = mSbox[cb[i + j]];
        }
    }
}

/**
 * @fn 4バイト単位の行を一定規則で左シフトする
 * @brief 4×4マスの1行目は左シフトせず、2行目は1左シフト、3行目は2左シフト、4行目は3左シフトする
 * @param _data 入力ファイルを読み込んだデータ
 */
void Encrypt::ShiftRows(int* _data)
{
    int i, j, i4;
    unsigned char* cb = (unsigned char*)_data;
    unsigned char cw[NBb];

    memcpy(cw, cb, sizeof(cw));

    for (i = 0; i < NB; i += 4)
    {
        i4 = i * 4;

        for (j = 1; j < 4; j++)
        {
            cw[i4 + j + 0 * 4] = cb[i4 + j + ((j + 0) & 3) * 4];
            cw[i4 + j + 1 * 4] = cb[i4 + j + ((j + 1) & 3) * 4];
            cw[i4 + j + 2 * 4] = cb[i4 + j + ((j + 2) & 3) * 4];
            cw[i4 + j + 3 * 4] = cb[i4 + j + ((j + 3) & 3) * 4];
        }
    }

    memcpy(cb, cw, sizeof(cw));
}

/**
 * @fn 掛け算
 * @param _dt 1バイトのバイナリデータ
 * @param _n 掛け算する対象の配列の添え字
 */
int Encrypt::Mul(int _dt, int _n)
{
    int i, x = 0;

    for (i = 8; i > 0; i >>= 1)
    {
        x <<= 1;

        if (x & 0x100)
        {
            x = (x ^ 0x1b) & 0xff;
        }  
        if (_n & i)
        {
            x ^= _dt;
        }
    }

    return x;
}

/**
 * @fn unsigned char型に変換
 * @param _data 入力ファイルを読み込んだデータ
 * @param _n 入力ファイルのデータ配列の添え字
 */
int Encrypt::Dataget(void* _data, int _n)
{
    return ((unsigned char*)_data)[_n];
}

/**
 * @fn ビット演算による４バイト単位の行列変換
 * @param _data 入力ファイルを読み込んだデータ
 */
void Encrypt::MixColumns(int* _data)
{
    int i, i4, x;

    for (i = 0; i < NB; i++)
    {
        i4 = i * 4;

        x = Mul(Dataget(_data, i4 + 0), 2) ^
            Mul(Dataget(_data, i4 + 1), 3) ^
            Mul(Dataget(_data, i4 + 2), 1) ^
            Mul(Dataget(_data, i4 + 3), 1);

        x |= (Mul(Dataget(_data, i4 + 1), 2) ^
            Mul(Dataget(_data, i4 + 2), 3) ^
            Mul(Dataget(_data, i4 + 3), 1) ^
            Mul(Dataget(_data, i4 + 0), 1)) << 8;

        x |= (Mul(Dataget(_data, i4 + 2), 2) ^
            Mul(Dataget(_data, i4 + 3), 3) ^
            Mul(Dataget(_data, i4 + 0), 1) ^
            Mul(Dataget(_data, i4 + 1), 1)) << 16;

        x |= (Mul(Dataget(_data, i4 + 3), 2) ^
            Mul(Dataget(_data, i4 + 0), 3) ^
            Mul(Dataget(_data, i4 + 1), 1) ^
            Mul(Dataget(_data, i4 + 2), 1)) << 24;

        _data[i] = x;
    }
}

/**
 * @fn ラウンド鍵とのXORをとる
 * @param _data 入力ファイルを読み込んだデータ
 * @param _roundCount ラウンド数
 */
void Encrypt::AddRoundKey(int* _data, int _roundCount)
{
    int i;

    for (i = 0; i < NB; i++)
    {
        _data[i] ^= mRoundKey[i + NB * _roundCount];
    }
}

/**
 * @fn Sboxによるbyte単位の置換
 * @param _in 回転処理した共通鍵
 */
int Encrypt::SubWord(int _in)
{
    int inw = _in;
    unsigned char* cin = (unsigned char*)&inw;

    cin[0] = mSbox[cin[0]];
    cin[1] = mSbox[cin[1]];
    cin[2] = mSbox[cin[2]];
    cin[3] = mSbox[cin[3]];

    return inw;
}

/**
 * @fn 1wordをbyte単位で左に回転する
 * @param _in 共通鍵のn番目
 */
int Encrypt::RotWord(int _in)
{
    int inw = _in, inw2 = 0;
    unsigned char* cin = (unsigned char*)&inw;
    unsigned char* cin2 = (unsigned char*)&inw2;

    cin2[0] = cin[1];
    cin2[1] = cin[2];
    cin2[2] = cin[3];
    cin2[3] = cin[0];

    return inw2;
}

/**
 * @fn 暗号化するための鍵の準備
 * @param _key 共通鍵
 */
void Encrypt::KeyExpansion(void* _key)
{
    int Rcon[10] = { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };
    int i, temp;

    memcpy(mRoundKey, _key, mKeyLength * 4);

    for (i = mKeyLength; i < NB * (mRound + 1); i++)
    {
        temp = mRoundKey[i - 1];

        if ((i % mKeyLength) == 0)
        {
            temp = SubWord(RotWord(temp)) ^ Rcon[(i / mKeyLength) - 1];
        }
        else if (mKeyLength > 6 && (i % mKeyLength) == 4)
        {
            temp = SubWord(temp);
        }
            
        mRoundKey[i] = mRoundKey[i - mKeyLength] ^ temp;
    }
}
