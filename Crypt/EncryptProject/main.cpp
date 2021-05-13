#include "pch.h"

/**
 * @fn コマンドライン引数のエラーチェック
 * @param argc 引数の個数
 * @param argv[] 引数文字列の配列へのポインタ
 * @return true:エラーなし(正常),false:エラー
 */
bool ErrorHandling(int argc, char* argv[])
{
    string commandLine1 = "-i";
    string commandLine3 = "-o";

    if (argc <= 1)
    {
        cout << "コマンドライン引数がありません" << endl;
        return false;
    }

    if (argc <= 3 && argc >= 2)
    {
        cout << "1番目のコマンドライン引数は'-i'で指定してください" << endl;
        cout << "3番目のコマンドライン引数は'-o'で指定してください" << endl;
        return false;
    }

    if (argc == 4)
    {
        if (argv[1] != commandLine1)
        {
            cout << "1番目のコマンドライン引数は'-i'で指定してください" << endl;

            return false;
        }

        if (argv[3] != commandLine3)
        {
            cout << "3番目のコマンドライン引数は'-o'で指定してください" << endl;

            return false;
        }
    }

    if (argc >= 6)
    {
        cout << "コマンドライン引数が多すぎます" << endl;
        return false;
    }

    if (argv[1] != commandLine1)
    {
        cout << "1番目のコマンドライン引数は'-i'で指定してください" << endl;

        if (argv[3] != commandLine3)
        {
            cout << "3番目のコマンドライン引数は'-o'で指定してください" << endl;
        }

        return false;
    }

    if (argv[3] != commandLine3)
    {
        cout << "3番目のコマンドライン引数は'-o'で指定してください" << endl;

        if (argv[1] != commandLine1)
        {
            cout << "1番目のコマンドライン引数は'-i'で指定してください" << endl;
        }

        return false;
    }

    return true;
}

int main(int argc, char* argv[])
{
    //コマンドライン引数のエラーチェック
    if (!ErrorHandling(argc, argv))
    {
        return 0;
    }

    //共通鍵の長さ
    int keyLength;

    while (true)
    {
        cout << "-------------------------------------------------------------------" << endl;
        cout << "共通鍵の長さを指定してください(4、6、8のいずれかを入力してください)" << endl;

        //共通鍵の長さを入力
        cin >> keyLength;

        //入力された数値が4,6,8だったらCBCモードのAES暗号化処理を行う
        if (keyLength == 4 || keyLength == 6 || keyLength == 8)
        {
            //CBCモードのAES暗号化
            Encrypt encrypt(argv[2], argv[4], keyLength);

            break;
        }
        else
        {
            cout << "入力した数値に誤りがあります" << endl;
        }

        cout << endl;
    }

    return 0;
}