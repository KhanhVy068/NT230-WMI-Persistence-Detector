# Tiến độ TV3

## Đã xong trước evaluation

- Detector R01–R04, API `analyze_normalized()`, CLI và Alert ID ổn định.
- Contract Normalizer/Detector/Alert, JSON Schema Draft 2020-12 và validation API/CLI.
- Regression development, test schema và harness Collector cho môi trường Python Store/UWP.
- Rà soát trước evaluation: phân biệt Consumer type không phân biệt hoa/thường; R04 không suy đoán lời gọi trực tiếp hay nhiều câu lệnh VBScript trên một dòng.

## Baseline evaluation

Commit hành vi trước evaluation: `3b01c8b6c75bb16be5a9328766e9b2c525f45e60`.

| File | SHA-256 |
|---|---|
| `detector/rules.py` | `1ADA1A454743F8AEDB163FEF4070CB7594290547C3B82C16B6FFDCAD2B87699E` |
| `detector/engine.py` | `664504931117454BE4B395D4890DA761F163FDD89C98CA7A9B157D1B1641A41C` |
| `detector/alert_generator.py` | `599A932E4C177799E98AF52F2EF39B760C9498FB7D5E15AE1B9183A1FD713616` |
| `detector/__init__.py` | `AFF86B174D5CFCBD791DDEB98CF9A15286B95FA28F986C252C2DA0E6F6D6148B` |

Evaluation chỉ được chạy sau baseline này. Nếu có sửa Detector sau khi đọc evaluation, cần ghi baseline/hash mới và giữ riêng kết quả chạy lại.

## Lệnh kiểm tra đã dùng

```powershell
$env:PYTHONUTF8 = "1"
python -X utf8 -m unittest discover -s tests -p test_detector.py -v
python -X utf8 -m unittest tests.test_schema -v
```

Với lỗi quyền `%TEMP%` của Python Store/UWP, dùng lệnh trong `docs/collector_dataset.md` gọi `tests/run_collector_tests.py`.

## Đang làm và bước tiếp theo

- Chạy evaluation lần đầu bằng baseline trên, lưu report từng Subscription và metrics theo Subscription/rule.
- Sau evaluation, hoàn thiện tài liệu học và checklist tích hợp/VM cho TV4.

## Chờ Windows VM

- Live test `TestLiveWindows` (WMI và Event Log thật) chưa chạy vì chưa có VM nhóm cung cấp.
- Không tải, cài hoặc khởi tạo VM trong phạm vi TV3.
