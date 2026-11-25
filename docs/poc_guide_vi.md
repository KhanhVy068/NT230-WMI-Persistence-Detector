# Hướng dẫn thực nghiệm WMI Persistence PoC

## 1. Giới thiệu

Tài liệu này hướng dẫn các thành viên trong nhóm sử dụng bộ công cụ do **TV1** xây dựng cho đồ án **Phát hiện cơ chế duy trì hiện diện bằng WMI Event Subscription**.

Bộ công cụ mô phỏng **WMI Permanent Event Subscription** (đăng ký sự kiện WMI tồn tại lâu dài) bằng các hành động lành tính: ghi chuỗi đánh dấu (*marker*) vào tệp nhật ký hoặc **Windows Event Log**. Bộ PoC **không** thực hiện kết nối điều khiển từ xa, đánh cắp dữ liệu hoặc chạy mã độc.

**Mục tiêu:** tạo kịch bản thử nghiệm, xác minh bộ ba **Event Filter – Event Consumer – Binding**, ghi lại kết quả thực nghiệm và dọn dẹp các đăng ký do nhóm tạo ra.

## 2. Môi trường thực nghiệm

- **Hệ điều hành:** Windows 10 trên máy ảo Oracle VirtualBox.
- **Quyền:** mở PowerShell dưới quyền **Administrator** trong **máy ảo**.
- **PowerShell:** PowerShell 7 cho các script chính; Windows PowerShell 5.1 để đăng ký nguồn nhật ký bằng `New-EventLog`.
- **Thư mục gốc của dự án:** `C:\WMI-Lab`.
- **Điều kiện an toàn:** máy ảo được cấp phép thử nghiệm và có snapshot để khôi phục khi cần.

Nếu PowerShell thông báo không cho phép chạy script `.ps1`, chỉ thay đổi chính sách cho phiên làm việc hiện tại:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

Chính sách trên chỉ có hiệu lực trong phiên PowerShell hiện tại. Không cần tắt Windows Defender hoặc Windows Firewall.

## 3. Cấu trúc dự án và chức năng

```text
C:\WMI-Lab\
├── poc\
│   ├── poc_generator_v2.ps1      # Tạo Event Filter, Consumer, Binding
│   ├── cleanup.ps1               # Kiểm tra và xóa đối tượng PoC
│   └── scenarios\
│       ├── P01.json              # Cấu hình P01
│       ├── P02.json              # Cấu hình P02
│       └── P03.json              # Cấu hình P03
├── automation\
│   └── scenario_runner.ps1       # Chạy và đánh giá từng kịch bản
├── docs\
│   └── poc_guide.md              # Tài liệu hướng dẫn này
└── results\                      # Nhật ký và kết quả JSON
```

Trong thư mục làm việc của TV1 có thể còn một số file sao lưu và file thử nghiệm cũ. Chúng **không bắt buộc** để chạy ba kịch bản chính.

## 4. Ba kịch bản thử nghiệm

| Kịch bản | Điều kiện kích hoạt | Loại Consumer | Nguồn xác minh | Marker kỳ vọng |
|---|---|---|---|---|
| **P01** | Bắt đầu tiến trình `notepad.exe` | `LogFileEventConsumer` | `C:\WMI-Lab\results\wmi_events.log` | `WMI_POC_SUCCESS` |
| **P02** | Bắt đầu tiến trình `CalculatorApp.exe` | `LogFileEventConsumer` | `C:\WMI-Lab\results\wmi_p02.log` | `WMI_P02_SUCCESS` |
| **P03** | Bắt đầu tiến trình `notepad.exe` | `NTEventLogEventConsumer` | Nhật ký **Application** của Windows | `WMI_P03_SUCCESS` |

Với P03, nguồn sự kiện (*Event Source*) là **`WMI-Lab-Test`**, mã sự kiện **`1003`**, loại sự kiện **Information (`EventType = 4`)**.

**Lưu ý:** P01 và P03 cùng theo dõi việc khởi chạy Notepad, nên khi mở Notepad cả hai Consumer có thể được kích hoạt. Cần phân biệt các kịch bản bằng tên Consumer và marker.

## 5. Chuẩn bị trước khi chạy

### 5.1. Mở PowerShell trong máy ảo

Mở **PowerShell (Administrator)**. Nếu vừa mở phiên mới và script bị chặn, dùng lệnh `Set-ExecutionPolicy` ở mục 2.

### 5.2. Đăng ký Event Source cho P03 (chỉ cần thực hiện khi chưa có)

`New-EventLog` có trong **Windows PowerShell 5.1**, không có trực tiếp trong PowerShell 7. Có thể chạy lệnh sau từ PowerShell 7, gọi Windows PowerShell 5.1 để đăng ký nguồn:

```powershell
powershell.exe -NoProfile -Command "if (-not [System.Diagnostics.EventLog]::SourceExists('WMI-Lab-Test')) { New-EventLog -LogName Application -Source 'WMI-Lab-Test' }"
```

Kiểm tra nguồn đã được đăng ký:

```powershell
[System.Diagnostics.EventLog]::SourceExists("WMI-Lab-Test")
```

Kết quả mong đợi: `True`.

**Chú ý:** Thao tác này tạo nguồn Event Log trên Windows; không phải tạo WMI Subscription. Không dùng `Write-EventLog` để thay thế bước kiểm thử WMI, vì ghi thủ công không chứng minh Consumer hoạt động.

## 6. Cách chạy từng kịch bản

Trong PowerShell Administrator của Windows VM, chạy **một dòng cho mỗi kịch bản**:

**P01**

```powershell
& "C:\WMI-Lab\automation\scenario_runner.ps1" -ScenarioId P01
```

**P02**

```powershell
& "C:\WMI-Lab\automation\scenario_runner.ps1" -ScenarioId P02
```

**P03**

```powershell
& "C:\WMI-Lab\automation\scenario_runner.ps1" -ScenarioId P03
```

Mỗi lượt chạy, `scenario_runner.ps1` thực hiện các việc chính:

1. Đọc file cấu hình `P01.json`, `P02.json` hoặc `P03.json`.
2. Gọi `poc_generator_v2.ps1` để tạo hoặc xác minh **Event Filter, Consumer, Binding**.
3. Kích hoạt tiến trình được cấu hình (Notepad hoặc Calculator).
4. Đợi khoảng **5 giây**.
5. Kiểm tra marker mới: **file `.log` đối với P01/P02**, **Windows Event Log đối với P03**.
6. Ghi kết quả dưới dạng JSON trong thư mục `results`.

Dòng `Scenario P0X PASSED!` nghĩa là trong lượt chạy có thêm marker phù hợp. Nếu không thấy marker mới, script có thể ghi `FAILED`. **PASSED/FAILED đánh giá việc chạy PoC, không phải độ chính xác của bộ phát hiện xâm nhập của TV3.**

## 7. Cách xem và kiểm tra kết quả

### 7.1. Xem kết quả JSON mới nhất cho cả ba kịch bản

```powershell
"P01","P02","P03" | ForEach-Object { $id=$_; Get-ChildItem "C:\WMI-Lab\results" -Filter "${id}*_result.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | ForEach-Object { Get-Content $_.FullName -Raw | ConvertFrom-Json } } | Select-Object scenario_id,consumer_type,verification_source,status,new_markers | Format-Table -AutoSize
```

Kết quả kỳ vọng sau khi kiểm thử thành công:

| Kịch bản | `consumer_type` | `verification_source` | `status` |
|---|---|---|---|
| P01 | `LogFileEventConsumer` | `LogFile` | `PASSED` |
| P02 | `LogFileEventConsumer` | `LogFile` | `PASSED` |
| P03 | `NTEventLogEventConsumer` | `WindowsEventLog` | `PASSED` |

Trường `new_markers` thường bằng `1` nếu chỉ có một lần kích hoạt trong thời gian thử. Kết quả thực tế có thể khác nếu nhiều tiến trình phù hợp cùng được khởi chạy.

### 7.2. Xem marker của P01 và P02

```powershell
Get-Content "C:\WMI-Lab\results\wmi_events.log" -Tail 10
```

```powershell
Get-Content "C:\WMI-Lab\results\wmi_p02.log" -Tail 10
```

### 7.3. Xem sự kiện P03 trong Windows Event Log

```powershell
Get-WinEvent -FilterHashtable @{LogName="Application"; ProviderName="WMI-Lab-Test"; Id=1003} -MaxEvents 10 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,ProviderName,Message
```

Kiểm tra thông điệp có chứa `WMI_P03_SUCCESS` và đối chiếu **thời gian tạo sự kiện**. Có thể tồn tại sự kiện thử ghi thủ công trước đó, chẳng hạn `WMI_P03_TEST_SUCCESS`.

## 8. Dọn dẹp WMI Subscription (Cleanup)

Sau khi thử nghiệm, dùng `cleanup.ps1` để xóa các đối tượng **do dự án tạo**. Script có hai chế độ:

**Preview – chỉ xem trước, không xóa:**

```powershell
& "C:\WMI-Lab\poc\cleanup.ps1" -ScenarioId P03
```

**Execute – xóa thật các đối tượng của kịch bản đã chọn:**

```powershell
& "C:\WMI-Lab\poc\cleanup.ps1" -ScenarioId P03 -Execute
```

Thay `P03` thành `P01` hoặc `P02` để chọn kịch bản khác. Script xóa theo thứ tự **Binding → Consumer → Filter**. Luôn chạy Preview trước và đối chiếu tên đối tượng. Chỉ dùng `-Execute` trong máy ảo được phép thử nghiệm.

Sau khi dọn P03, có thể kiểm tra lại bằng:

```powershell
& "C:\WMI-Lab\poc\cleanup.ps1" -ScenarioId P03
```

Kết quả kỳ vọng: `Filter found: False`, `Consumers found: 0`, `Bindings found: 0`.

Nếu muốn khôi phục và thử lại P03:

```powershell
& "C:\WMI-Lab\automation\scenario_runner.ps1" -ScenarioId P03
```

**Không xóa các Consumer hệ thống**, chẳng hạn `SCM Event Log Consumer`.

## 9. Kiểm thử duy trì qua khởi động lại (Persistence)

Để kiểm chứng Subscription tồn tại sau khi khởi động lại máy ảo:

1. Chạy kịch bản để tạo đủ Filter, Consumer và Binding.
2. Ghi nhận marker hoặc sự kiện hiện có.
3. **Khởi động lại Windows VM** (không khôi phục snapshot sạch ở giữa phép thử).
4. Mở PowerShell Administrator và kích hoạt lại tiến trình tương ứng.
5. Kiểm tra file log (P01/P02) hoặc Windows Event Log (P03) xem có marker mới.
6. Sau khi hoàn tất, chạy Cleanup nếu không cần giữ Subscription để tích hợp với các thành viên khác.

Thử nghiệm trước đó đã xác minh khả năng duy trì sau reboot đối với cấu hình WMI dùng file log. **P03 dùng NTEventLogEventConsumer là biến thể mới; cần kiểm thử lại riêng sau reboot nếu muốn kết luận đã xác minh persistence của P03.**

## 10. An toàn và phạm vi sử dụng

- Chỉ chạy trên **Windows VM trong môi trường lab được phép**.
- Giữ snapshot sạch để có thể khôi phục hệ thống.
- Chỉ ghi marker lành tính; không sử dụng payload độc hại.
- Không thiết lập C2, đánh cắp thông tin đăng nhập hay truyền dữ liệu ra ngoài.
- Không vô hiệu hóa Defender/Firewall để chạy bộ PoC.
- Khi kết thúc thực nghiệm, dọn các Subscription do dự án tạo.

## 11. Hạn chế hiện tại

- Generator hỗ trợ hai loại Consumer: `LogFileEventConsumer` và `NTEventLogEventConsumer`.
- P01 và P03 cùng theo dõi tiến trình Notepad; các kịch bản chưa hoàn toàn độc lập về điều kiện kích hoạt.
- Runner đợi cố định khoảng **5 giây** trước khi kiểm tra marker.
- Runner có thể chưa ghi JSON nếu phát sinh lỗi trước giai đoạn xác minh marker.
- Nguồn Event Log `WMI-Lab-Test` cần được đăng ký trước khi chạy P03 trên máy ảo mới.
- Dữ liệu đánh giá PoC chưa tương đương với dữ liệu đánh giá hiệu năng của bộ phát hiện; cần tích hợp và kiểm thử thêm với TV2, TV3, TV4.

## 12. Gợi ý bàn giao cho nhóm

Bàn giao tối thiểu các file:

- `poc/poc_generator_v2.ps1`
- `poc/cleanup.ps1`
- `poc/scenarios/P01.json`, `P02.json`, `P03.json`
- `automation/scenario_runner.ps1`
- `docs/poc_guide.md`
- Một số file JSON kết quả tiêu biểu trong `results/` (sau khi rà soát không chứa dữ liệu riêng tư)

Không cần đưa các file `*_backup.ps1`, `*_backup.json` và nhật ký thử lỗi cũ vào gói bàn giao chính. Người nhận cần biết các script đang dùng đường dẫn `C:\WMI-Lab` và phải chuẩn bị thư mục tương ứng trên Windows VM.
