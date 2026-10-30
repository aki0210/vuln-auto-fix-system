import os
import sys
import subprocess
os.environ["PYTHONIOENCODING"] = "utf-8" # Windowsのコンソールの文字化けを防ぐおまじない
sys.stdout.reconfigure(encoding="utf-8")
import os
import re
import numpy as np
import time
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Input, LSTM, Dense, Dropout, SpatialDropout1D
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.optimizers import Adam

#第1工程: データの前処理
BASE_DIR = "./data"
CATEGORIES =  ["cwe78", "cwe79", "cwe89", "cwe90", "cwe91", "cwe95", "cwe98", "cwe601"]
for cat in CATEGORIES:
    os.makedirs(os.path.join(BASE_DIR,cat),exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR,f"{cat}safe"),exist_ok=True)

def load_php_files(folder_path,label):
    codes,labels=[],[]
    if not os.path.exists(folder_path):
        return codes,labels
    for filname in os.listdir(folder_path):
        if filname.endswith(".php"):
            with open(os.path.join(folder_path, filname), "r", encoding="utf-8") as f:
                codes.append(f.read())
                labels.append(label)
    return codes, labels

#第2工程： データのベクトル化
all_codes,all_labels=[],[]
safe_count,unsafe_count=0,0
for cat in CATEGORIES:
    codes,labels=load_php_files(os.path.join(BASE_DIR,f"{cat}safe"),0)
    all_codes.extend(codes)
    all_labels.extend(labels)
    safe_count += len(codes)
for i, cat in enumerate(CATEGORIES, start=1):
    codes, labels = load_php_files(os.path.join(BASE_DIR, cat), i)
    all_codes.extend(codes)
    all_labels.extend(labels)
    unsafe_count += len(codes)

#第3工程： データのトークン化とパディング
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.layers import Embedding
from sklearn.utils.class_weight import compute_class_weight
from tensorflow.keras.callbacks import EarlyStopping
print("Keras Tokenizerでテキストを処理中...")
tokenizer = Tokenizer(oov_token="<OOV>", filters='!"#%&\'()*+,-./:;<=>?@[\\]^`{|}~\t\n') #改行や記号を誤ってトークン化しないようにフィルタリング
tokenizer.fit_on_texts(all_codes) #集めたすべてのコードをトークン化して、単語の辞書を作成する
sequences = tokenizer.texts_to_sequences(all_codes) #単語ごとにID化されたシーケンスに変換する　数字の羅列に変更
vocab_size = len(tokenizer.word_index) +1 
sequence_length =200
X = pad_sequences(sequences, maxlen=sequence_length, padding='post', truncating='post')
y = np.array(all_labels)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y) #このrandom_state42の42は、乱数のシード値で、同じデータ分割を再現するために使用されます。

#第4工程：LSTMモデルの構築
model = Sequential([Input(shape=(sequence_length,)),Embedding(input_dim=vocab_size, output_dim=100, mask_zero=True),
LSTM(64),Dropout(0.5),Dense(10,activation='softmax')]) #LSTM神経数 Dropoutは過学習防止のために追加
model.compile(optimizer=Adam(),loss='sparse_categorical_crossentropy',metrics=['accuracy']) #optimizer=Adam()は、モデルの学習を最適化するためのアルゴリズム
weights_array=compute_class_weight(class_weight='balanced',classes=np.unique(y_train),y=y_train)
weights_array=np.sqrt(weights_array)
class_weights_dict=dict(enumerate(weights_array))
print("\n--- 適用するクラスの重み ---")
for cls,weight in class_weights_dict.items():
    print(f"クラス{cls}: {weight:.4f}")
early_stopping=EarlyStopping(monitor='val_loss',patience=2,restore_best_weights=True) #patience=2は、2エポック連続で改善が見られない場合に学習を停止することを意味します。
print("\n-- 学習開始 ---")
history=model.fit(X_train,y_train,epochs=20,batch_size=256,validation_data=(X_test,y_test),
verbose=2,class_weight=class_weights_dict,callbacks=[early_stopping])

#第5工程：モデルの評価
print("\n--- データ情報 ---")
print(f"Safeコード数: {safe_count}")
print(f"Unsafeコード数: {unsafe_count}")
print(f"全コード数: {len(all_codes)}")
print(f"X shape: {X.shape}")
print(f"Y shape: {y.shape}")
print(f"学習データ数: {len(X_train)}")
print(f"評価データ数: {len(X_test)}")
loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
print(f"\n評価データの正解率: {accuracy:.4f}")
print(f"評価データの損失: {loss:.4f}")

#第6工程： 混同行列と分類レポートの表示
y_pred=np.argmax(model.predict(X_test),axis=1)
print("\n--- 混同行列 ---")
print(confusion_matrix(y_test,y_pred))
target_names=["Safe"] + [cat.upper().replace("CWE", "CWE-") for cat in CATEGORIES]
print("\n--- 分類レポート ---")
print(classification_report(y_test,y_pred,target_names=target_names,digits=4)) 

#第7工程：実データによる推論テスト
CVE_DIR = "./cve_test_data"
os.makedirs(CVE_DIR, exist_ok=True)
print("\n--- 実データの推論テスト ---")
cve_files = [f for f in os.listdir(CVE_DIR) if f.endswith('.php')] # フォルダ内のPHPファイルを取得
if not cve_files:
    print(f"'{CVE_DIR}' フォルダにテスト用のPHPファイルが見つかりません。")
    print(f"実際のCVEコードなどを '{CVE_DIR}' フォルダに保存して、再度実行してみてください。")
else:
    cve_codes = []
    for filename in cve_files:
        with open(os.path.join(CVE_DIR, filename), "r", encoding="utf-8") as f:
            cve_codes.append(f.read())
    print(f"{len(cve_files)}件のファイルを解析中...\n")
    cve_sequences = tokenizer.texts_to_sequences(cve_codes)  # 1. 前処理 (★ここが重要: 学習時に作ったtokenizerをそのまま使う！)
    cve_X = pad_sequences(cve_sequences, maxlen=sequence_length, padding='post', truncating='post')
    predictions = model.predict(cve_X, verbose=0)  # 2. AIによる推論 (予測)
    predicted_classes = np.argmax(predictions, axis=1)
    for i, filename in enumerate(cve_files):  # 3. 結果の出力
        print(f"【デバッグ】AI視点 ({filename}): {cve_sequences[i]}")
        pred_idx = predicted_classes[i]
        pred_label = target_names[pred_idx] # 例: "Safe" や "CWE-79"
        confidence = predictions[i][pred_idx] * 100 # その答えに対するAIの自信（確率）
        print(f"ファイル: {filename}")
        if pred_label == "Safe": # 結果を見やすく色分け（Windowsのターミナル等で対応）
            print(f" ➔ 🟢 予測結果: {pred_label} (確信度: {confidence:.3f}%)")
        else:
            print(f" ➔ 🔴 予測結果: {pred_label} (確信度: {confidence:.3f}%)")
        sorted_indices = np.argsort(predictions[i])[::-1]  # AIが次に迷った「第2候補」も表示すると分析に便利です
        second_idx = sorted_indices[1]
        second_label = target_names[second_idx]
        second_conf = predictions[i][second_idx] * 100
        print(f" [第2候補: {second_label} ({second_conf:.3f}%)]")
        print("-" * 40)
print("\n--- 辞書（Tokenizer）の登録チェック ---")
print("evalのID:", tokenizer.word_index.get("eval", "未登録 (OOV)"))
print("$_GETのID:", tokenizer.word_index.get("$_get", "未登録 (OOV)")) # Kerasは自動で小文字化するため小文字で検索

#第8工程：LLMによる脆弱性の詳細解説と修正案の生成
from google import genai
client=genai.Client(api_key="")#
print("\n--- LLMによる脆弱性の修正と自己修復（再検証）ループ ---")

def validate_fixed_code(file_path):
    if not os.path.exists(file_path):
        return False,"File System","ファイルが見つかりません"
    syntax_result=subprocess.run(
        [r"C:\php\php.exe","-l",file_path],
        capture_output=True,text=True,check=False
    )
    if syntax_result.returncode !=0:
        return False,"構文エラー",syntax_result.stderr.strip() if syntax_result.stderr else syntax_result.stdout.strip()
    security_result = subprocess.run(
        [
            r"C:\php\php.exe", 
            "-d", "error_reporting=E_ALL&~E_DEPRECATED",
            "-d", "display_errors=stderr",
            r"C:\php\progpilot.phar",
            file_path
        ],
        capture_output=True, text=True, check=False
    )
    output = security_result.stdout.strip()
    if not output or output == "[]":
        return True, "ALL PASS", "クリア"
    else:
        return False, "静的解析エラー (Progpilot)", output 
def predict_vulnerability(code_text): #LSTM予想関数
    seq = tokenizer.texts_to_sequences([code_text])
    pad = pad_sequences(seq, maxlen=sequence_length, padding='post', truncating='post')
    pred = model.predict(pad, verbose=0)
    pred_idx = np.argmax(pred, axis=1)[0]
    label = target_names[pred_idx]
    confidence = pred[0][pred_idx] * 100
    return label, confidence
def extract_php_code(gemini_response_text): #Geminiの回答からPHPコードを抽出する関数
    pattern = r"```php\s*(.*?)\s*```" # ```php と ``` で囲まれたブロックを正規表現で抽出
    match = re.search(pattern, gemini_response_text, re.DOTALL | re.IGNORECASE)  # re.IGNORECASE をつけると、Geminiが万が一 ```PHP と大文字で返してきても対応できます
    if match:
        return match.group(1)
    return None
def save_temp_php(code_str, output_path="temp_fixed.php"): #テキストをファイルに保存する関数
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(code_str)
    return output_path
for i, filename in enumerate(cve_files):
    code_content = cve_codes[i]
    pred_label, confidence = predict_vulnerability(code_content)
    
    if pred_label != "Safe":
        print(f"\n[{filename}] 🔴 {pred_label} を検知しました。Geminiで修正案を生成中...")
        
        prompt = f"""あなたは熟練のセキュリティエンジニアです。
        以下のPHPコードには脆弱性（{pred_label}）が存在します。
        1. 脆弱性の根本原因
        2. 攻撃シナリオ
        3. 修正後の完全なコード（既存の処理を省略せず、必ず ```php と ``` で囲んで出力してください）
        【対象コード】
        {code_content}"""
        try:
            response = client.models.generate_content(model="gemini-3.5-flash", contents=prompt) #geminiに質問を投げ、回答をもらう 開発時点はgemini-3.8-flashを使い、本番はgemini-3.1-pro-previewを使う
            print(f"【Geminiの解説】\n{response.text}\n")
            print("-" * 40)
            print(f" [{filename}] 修正コードの抽出と再検証を開始します...")
            fixed_code = extract_php_code(response.text)
            if fixed_code:
                save_path = os.path.join(CVE_DIR, f"fixed_{filename}")
                saved_filename = save_temp_php(fixed_code, output_path=save_path)
                print(f"構文チェック＆静的解析ツールによる検証を開始...")
                is_safe, gate_name, details = validate_fixed_code(saved_filename)
                if is_safe:
                    print(f"【門番クリア】完璧な修正です！ '{saved_filename}' を保存します。")
                    # 研究比較用：門番をクリアしたコードを、LSTMはどう判定するか？
                    re_label, re_conf = predict_vulnerability(fixed_code)
                    print(f"LSTMの再検証結果: {re_label} (確信度: {re_conf:.2f}%)")
                else:
                    print(f"[門番による破棄】{gate_name} で弾かれました。")
                    print(f"▼ エラー詳細:\n{details}")
                    # 不完全なコードなのでファイルを削除する（必要に応じて残してもOK）
                    os.remove(saved_filename)
                    print("不完全なため修正案を破棄しました。")
            else:
                print("Geminiの回答からPHPコードを抽出できませんでした。")      
        except Exception as e:
            print(f"エラーが発生しました: {e}")
        time.sleep(4)    
    else:
        print(f"\n[{filename}] 🟢 最初からSafe判定のためスキップします。")
print("\n全自動の自己修復パイプラインが完了しました！")
