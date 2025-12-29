# AnLF 推理結果分析工具

用於分析 AnLF 系統的推理結果，生成混淆矩陣、KPI 指標和視覺化報告。

## 快速開始

### 安裝依賴
```bash
pip3 install -r requirements.txt
```

### 基本用法
```bash
python3 analyze_inference.py <csv_file> <attacker_range> [-o output_dir]
```

### 範例
```bash
# 分析 CSV 檔案，攻擊者範圍 46-50，輸出到同目錄
python3 analyze_inference.py inference_20251225_092222.csv 46-50

# 指定輸出目錄
python3 analyze_inference.py inference_20251225_092222.csv 46-50 -o /path/to/output

# 只生成報告，不生成圖表
python3 analyze_inference.py inference_20251225_092222.csv 46-50 --no-plots
```

## 功能

### 混淆矩陣 (Confusion Matrix)
- **TP**: 攻擊者被正確檢測
- **FP**: 正常用戶被誤判
- **TN**: 正常用戶被正確識別
- **FN**: 攻擊者被漏判

### 關鍵效能指標 (KPI)

$$\text{Precision} = \frac{TP}{TP + FP}$$ - 精確率

$$\text{Recall} = \frac{TP}{TP + FN}$$ - 召回率

$$F1 = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$ - F1-Score

$$FPR = \frac{FP}{TN + FP}$$ - 假正率（電信商最關注）

### 視覺化圖表
- **confusion_matrix_*.png**: 混淆矩陣熱力圖
- **risk_distribution_*.png**: 風險分數分布圖
- **risk_progression_*.png**: 風險進展趨勢圖
- **roc_curve_*.png**: ROC 曲線

### 報告導出
- **analysis_report_*.json**: 詳細的分析結果（JSON 格式）

## CSV 數據格式要求

必需欄位：
- `supi`: 用戶標識 (格式: `imsi-XXXXXXXXXXX??`)
- `risk_score`: 風險分數 (0-100)
- `is_blocked`: 是否被阻擋 (true/false)
- `attack_detected`: 是否檢測到攻擊 (true/false)

## 時序數據處理

工具會自動取**每個用戶的最後一條記錄**作為最終狀態進行分析。

## 命令行選項

```
usage: analyze_inference.py [-h] [-o OUTPUT_DIR] [--no-plots] csv_file attacker_range

位置參數:
  csv_file           推理結果 CSV 檔案
  attacker_range     攻擊者範圍，格式: start-end (例如: 46-50)

可選參數:
  -h, --help         顯示幫助信息
  -o, --output-dir   輸出目錄 (預設為 CSV 同目錄)
  --no-plots         只生成報告，不生成圖表
```

## 論文寫作

### 混淆矩陣表格

| 指標 | 值 |
|------|-----|
| TP | 5 |
| FP | 0 |
| TN | 45 |
| FN | 0 |
| Precision | 100% |
| Recall | 100% |
| F1-Score | 1.0000 |
| FPR | 0% |

### 在論文中引用

> 表 X 展示了系統的性能評估。在 50 個測試用戶中（5 個攻擊者，45 個正常用戶），
> 系統達到了 100% 的精確率和 100% 的召回率，特別地假正率（FPR）為 0%。

## 常見問題

| 問題 | 解決方案 |
|------|---------|
| UE 編號提取不對？ | 確保 SUPI 格式為 `imsi-208930000000XXX` |
| 圖表顯示中文亂碼？ | 字體問題，不影響數據正確性 |
| 分析多個範圍？ | 多次運行程式，每次指定不同的攻擊者範圍 |
| 只生成報告？ | 使用 `--no-plots` 選項 |

## 依賴

- Python 3.6+
- pandas, numpy, matplotlib, seaborn, scikit-learn
