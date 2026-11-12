D12-WMI-Persistence-Detector/
│
├── poc/                        # TV1 – PoC & Automation
│   ├── generator.ps1            # Tạo WMI Subscription
│   ├── cleanup.ps1              # Xóa Subscription
│   ├── scenario_runner.py       # Tự động chạy kịch bản
│   └── scenarios/               # Cấu hình các kịch bản PoC
│
├── collector/                  # TV2 – Telemetry & Dataset
│   ├── wmi_collector.py         # Thu thập Filter, Consumer, Binding
│   ├── eventlog_collector.py    # Thu thập Windows Event Logs
│   └── normalizer.py            # Chuẩn hóa dữ liệu
│
├── detector/                   # TV3 – Detection Engine
│   ├── engine.py                # Phân tích Subscription
│   ├── rules.py                 # Detection Rules
│   └── alert_generator.py       # Xuất cảnh báo
│
├── application/                # TV4 – Application & Evaluation
│   ├── app.py                   # Giao diện chính
│   ├── integration.py           # Kết nối các module
│   └── evaluation.py            # Tính Precision, Recall, F1, FPR
│
├── schemas/                    # Cấu trúc JSON dùng chung
│   ├── subscription.schema.json
│   └── alert.schema.json
│
├── dataset/                    # Dữ liệu thực nghiệm
│   ├── benign/
│   └── poc/
│
├── samples/                    # JSON mẫu để lập trình độc lập
│   ├── subscriptions.sample.json
│   └── alerts.sample.json
│
├── tests/                      # Kiểm thử các module
│   ├── test_collector.py
│   ├── test_detector.py
│   └── test_integration.py
│
├── docs/                       # Tài liệu đồ án
│   ├── architecture.md
│   ├── vm_setup.md
│   └── user_guide.md
│
├── requirements.txt
├── .gitignore
└── README.md
