# Evaluation TV3 trên dataset mô phỏng

Tài liệu này ghi hai lần chạy evaluation liên tiếp. Không có nhãn nào bị sửa hoặc bị loại sau khi xem kết quả lần đầu. Dataset là synthetic, `vm_verified=false`; các chỉ số dưới đây không thay thế thử nghiệm trên Windows VM độc lập.

## Cách chạy

```powershell
$env:PYTHONUTF8 = "1"
python -X utf8 tools/evaluate_detector.py `
  --baseline <detector-baseline-sha> `
  --output results/tv3_evaluation_baseline_<short-sha>.json
```

Harness chỉ dùng `dataset/labels.json` sau khi TV3 đã tạo report. Detector không import harness và không dùng labels, ID, đường dẫn file hay split để quyết định Alert.

Mỗi file kết quả giữ `analysis`, `alerts`, predicted/expected rule IDs và policy metric cho từng Subscription. Nó tính:

- **Mức Subscription:** positive khi `matched_rule_ids` không rỗng.
- **Mức rule:** một cặp `(subscription, rule)` positive khi rule thuộc `expected_rule_ids`/`predicted_rule_ids`.
- **Micro rule metric:** gộp mọi cặp Subscription/rule.
- Precision, Recall và FPR là `null` nếu mẫu số riêng của metric đó bằng 0.
  F1 dùng trực tiếp `2*TP/(2*TP+FP+FN)` và chỉ là `null` khi mẫu số F1
  bằng 0; không thay bất kỳ metric nào bằng 0 hoặc 1 khi mẫu số của nó bằng 0.
- Mẫu `incomplete` hoặc có `unanalysed_forms` vẫn được tính metric và được báo riêng trong coverage; không có mẫu nào bị loại.

## Lần đầu — baseline `3b01c8b`

File: [tv3_evaluation_baseline_3b01c8b.json](../results/tv3_evaluation_baseline_3b01c8b.json)

| Mức Subscription | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Kết quả | 3 | 0 | 4 | 1 | 1.0 | 0.75 | 0.8571 | 0.0 |

R03 có một FN là S006. Mẫu cấu hình `cscript.exe` với script tĩnh trong Downloads; implementation khi đó chỉ xem executable `cscript.exe`, chưa trích script argument. Kết quả này được giữ nguyên để truy vết.

## Lần chạy lại — baseline `900f70b`

File: [tv3_evaluation_baseline_900f70b.json](../results/tv3_evaluation_baseline_900f70b.json)

Sau lần đầu, commit `900f70b` bổ sung source R03 tĩnh cho `cscript.exe`/`wscript.exe`: bỏ qua option bắt đầu `/` hoặc `//`, lấy path tĩnh đầu tiên làm `script_host_file`, và chỉ sau đó phân loại nhóm path. Bản sửa có regression test, schema evidence và scope/documentation cập nhật.

| Mức Subscription | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Kết quả | 4 | 0 | 4 | 0 | 1.0 | 1.0 | 1.0 | 0.0 |

| Rule | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| R01 | 0 | 0 | 8 | 0 | null | null | null | 0.0 |
| R02 | 1 | 0 | 7 | 0 | 1.0 | 1.0 | 1.0 | 0.0 |
| R03 | 4 | 0 | 4 | 0 | 1.0 | 1.0 | 1.0 | 0.0 |
| R04 | 0 | 0 | 8 | 0 | null | null | null | 0.0 |
| Rule micro | 5 | 0 | 27 | 0 | 1.0 | 1.0 | 1.0 | 0.0 |

`null` ở R01/R04 không nói detector tốt hay xấu: split evaluation không có label positive cho hai rule này, nên Precision/Recall/F1 không có mẫu số phù hợp.

## Coverage và giới hạn

Tất cả 8 Subscription evaluation được chạy. Có 7 complete và một partial:

- S023 vẫn tạo Alert R03 từ `script_file_name` Temp, nhưng thiếu `script_text`; R04 là `insufficient_data` và report giữ `unavailable_fields`/`unanalysed_forms`.
- S013, S017 và S023 có ít nhất một `unanalysed_forms`. Chúng vẫn ở trong metric để không làm đẹp kết quả bằng cách bỏ coverage khó.
- Kết quả chỉ đánh giá policy R01–R04 và parser hiện tại trên synthetic dataset. Không suy ra file tồn tại, quyền ghi, thực thi thật hoặc tính độc hại ngoài policy lab.

Trước khi công bố kết luận vận hành, chạy lại cùng lệnh trên dữ liệu VM độc lập và báo riêng coverage/partial theo cùng policy.
