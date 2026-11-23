# Tiến độ TV3

## Đã xong trước evaluation

- Detector R01–R04, API `analyze_normalized()`, CLI và Alert ID ổn định.
- Contract Normalizer/Detector/Alert, JSON Schema Draft 2020-12 và validation API/CLI.
- Regression development, test schema và harness Collector cho môi trường Python Store/UWP.
- Rà soát trước evaluation: phân biệt Consumer type không phân biệt hoa/thường; R04 không suy đoán lời gọi trực tiếp hay nhiều câu lệnh VBScript trên một dòng.
- Evaluation lần đầu và lần chạy lại được giữ riêng trong `results/`; lỗi coverage `cscript/wscript` R03 đã có regression test và scope cập nhật.
- Tài liệu TV4, checklist VM và tài liệu học TV3 bám code hiện tại.

## Baseline và lịch sử evaluation

### Lần đầu — giữ nguyên

Commit hành vi: `3b01c8b6c75bb16be5a9328766e9b2c525f45e60`.

| File | SHA-256 |
|---|---|
| `detector/rules.py` | `1ADA1A454743F8AEDB163FEF4070CB7594290547C3B82C16B6FFDCAD2B87699E` |
| `detector/engine.py` | `664504931117454BE4B395D4890DA761F163FDD89C98CA7A9B157D1B1641A41C` |
| `detector/alert_generator.py` | `599A932E4C177799E98AF52F2EF39B760C9498FB7D5E15AE1B9183A1FD713616` |
| `detector/__init__.py` | `AFF86B174D5CFCBD791DDEB98CF9A15286B95FA28F986C252C2DA0E6F6D6148B` |

Evaluation chỉ được chạy sau baseline này. Nếu có sửa Detector sau khi đọc evaluation, cần ghi baseline/hash mới và giữ riêng kết quả chạy lại.

Kết quả evaluation đầu tiên lưu ở `results/tv3_evaluation_baseline_3b01c8b.json`: subscription TP=3, FP=0, TN=4, FN=1; Precision=1.0, Recall=0.75, F1≈0.8571, FPR=0. S006 là FN R03 vì đường dẫn script tĩnh sau `cscript.exe` chưa được trích xuất.

### Lần chạy lại sau sửa coverage R03

Commit hành vi: `900f70bc5f90d69a45f5991b500e6c269416c105`.

| File | SHA-256 |
|---|---|
| `detector/rules.py` | `BB40C71B7E94B0B43C182756AE63E71636CAD078D1A3E64C5A5F07BE69251196` |
| `detector/engine.py` | `8D9A5CA2F7E40AF7BB7B2384B60D4AC98D26EA017D786C69101591D48E5686C4` |
| `detector/alert_generator.py` | `599A932E4C177799E98AF52F2EF39B760C9498FB7D5E15AE1B9183A1FD713616` |
| `detector/__init__.py` | `AFF86B174D5CFCBD791DDEB98CF9A15286B95FA28F986C252C2DA0E6F6D6148B` |

Kết quả chạy lại đã lưu ở `results/tv3_evaluation_baseline_900f70b.json`: subscription TP=4, FP=0, TN=4, FN=0; Precision=Recall=F1=1.0, FPR=0. File lần đầu vẫn được giữ để thể hiện phát hiện S006 và thay đổi sau đó.

## Lệnh kiểm tra đã dùng

```powershell
$env:PYTHONUTF8 = "1"
python -X utf8 -m unittest discover -s tests -p test_detector.py -v
python -X utf8 -m unittest tests.test_schema -v
```

Với lỗi quyền `%TEMP%` của Python Store/UWP, dùng lệnh trong `docs/collector_dataset.md` gọi `tests/run_collector_tests.py`.

## Đang làm và bước tiếp theo

- Chạy live test khi có Windows VM nhóm cung cấp.
- TV4 tích hợp qua API/schema và mở PR từ `feature/detection-engine` vào nhánh chung khi nhóm sẵn sàng.

## Chờ Windows VM

- Live test `TestLiveWindows` (WMI và Event Log thật) chưa chạy vì chưa có VM nhóm cung cấp.
- Không tải, cài hoặc khởi tạo VM trong phạm vi TV3.
