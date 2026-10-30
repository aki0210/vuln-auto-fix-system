import subprocess
import os
def check_security_progpilot(file_path):
    """
    Progpilotを使ってPHPファイルの脆弱性を静的解析する関数
    戻り値:脆弱性がなけらば、True、発見されればFalse
    """
    if not os.path.exists(file_path):
        print(f"ファイルが見つかりません:{file_path}")
        return False
    try:
        result=subprocess.run(
            [r"C:\php\php.exe",
             "-d","error_reporting=E_ALL & ~E_DAEPRECATED",
             "-d","display_errors=stderr",
             r"C:\php\progpilot.phar",file_path],
            capture_output=True,
            text=True,
            check=False 
        )
        output=result.stdout.strip()
        if not output or output=="[]":
            print(f"[PASS]脆弱性は見つかりませんでした（安全）:{file_path}")
            return True
        else:
            print(f"[FAIL]脆弱性を検知しました（逮捕）:{file_path}")
            print("--- Progpilotのレポート")
            print(output)
            print("-------------------------------------")
            return False
    except Exception as e:
        print(f"解析中にエラーが発生しました:{e}")
        return False

if __name__ == "__main__":
    target_file="./data/gemini_safe/fixed_test_cwe90.php"
    print(f"--- {target_file}のセキュリティ解析を開始します ---")
    is_valid=check_security_progpilot(target_file)
    if is_valid:
        print("安全なコードとして、修正案を起用します")
    else:
        print("脆弱性が残っているため、修正案を破棄します")
