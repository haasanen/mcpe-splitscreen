// Copyright (c) 2026 haasanen — SPDX-License-Identifier: GPL-3.0-only
// mcpe-control — GUI control panel for four-instance Minecraft Bedrock splitscreen.
// Each instance gets its own gamepad chosen from a dropdown; one button starts
// everything; windows are auto-tiled. No config files needed by the player.
#include <QApplication>
#include <QComboBox>
#include <QDir>
#include <QFile>
#include <QFileInfoList>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QRegularExpression>
#include <QScreen>
#include <QTextStream>
#include <QTimer>
#include <QVBoxLayout>
#include <QProcess>

struct Instance {
    QString name;      // p1..p4
    QComboBox* pad;
    QPushButton* toggle;
    QLabel* status;
    qint64 pid = -1;
    QPoint pos;        // tiled position
    QSize size;        // tiled size
};

static QString root() {
    return QCoreApplication::applicationDirPath() + "/..";  // bin/../ == release root
}
static QString home() {
    const char* h = qgetenv("MCPE_HOME");
    if (h && *h) return h;
    return QDir::homePath() + "/.local/share/mcpe-splitscreen";
}

static void writeConf(const QString& name, const QString& padPath, const QSize& size) {
    QDir().mkpath(root() + "/conf");
    QFile f(root() + "/conf/instance-" + name + ".conf");
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) return;
    QTextStream ts(&f);
    ts << "MCPE_PAD=" << padPath << "\n"
       << "MCPE_GEOM=" << size.width() << "x" << size.height() << "\n";
}

static QString readConfPad(const QString& name) {
    QFile f(root() + "/conf/instance-" + name + ".conf");
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return {};
    for (const auto& line : QString::fromUtf8(f.readAll()).split('\n')) {
        if (line.startsWith("MCPE_PAD=")) return line.mid(9).trimmed();
    }
    return {};
}

static QStringList padPaths() {
    QStringList out;
    for (const auto& e : QDir("/dev/input/by-id").entryList(QDir::Files | QDir::NoDotAndDotDot | QDir::System)) {
        if (e.endsWith("-joystick")) out << "/dev/input/by-id/" + e;
    }
    out.sort();
    return out;
}

static QString padFriendly(const QString& path) {
    QString s = path.section("/by-id/", -1);
    s.replace("-joystick", "");
    s.replace("usb-", "");
    return s;
}

static qint64 readPid(const QString& name) {
    QFile f(home() + "/instances/" + name + "/pid");
    if (!f.open(QIODevice::ReadOnly)) return -1;
    return f.readAll().trimmed().toLongLong();
}

static bool alive(qint64 pid) {
    if (pid <= 0) return false;
    return QFileInfo::exists(QString("/proc/%1").arg(pid));
}

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    if (QStringList(app.arguments()).contains("--check")) {  // CI/headless smoke
        QTextStream out(stdout);
        out << "mcpe-control ok, pads found: " << padPaths().size() << "\n";
        return 0;
    }
    QApplication::setApplicationName("mcpe-control");

    // tile layout: 2x2 grid on the primary screen
    const QRect scr = QApplication::primaryScreen()->geometry();
    const int tw = scr.width() / 2, th = scr.height() / 2;

    QWidget win;
    win.setWindowTitle("Minecraft — 4 Player Splitscreen");
    QVBoxLayout* v = new QVBoxLayout(&win);

    // big start-all button + server row
    QHBoxLayout* top = new QHBoxLayout;
    QPushButton* startAll = new QPushButton("▶  START ALL FOUR");
    QFont big = startAll->font(); big.setPointSize(big.pointSize() + 10); big.setBold(true);
    startAll->setFont(big); startAll->setMinimumHeight(90);
    QPushButton* serverBtn = new QPushButton("Server: Start");
    QLabel* serverState = new QLabel("server stopped");
    top->addWidget(startAll, 2);
    top->addWidget(serverBtn, 1);
    top->addWidget(serverState, 1);
    v->addLayout(top);

    QGridLayout* grid = new QGridLayout;
    const char* labels[4] = {"Player 1 (blue)", "Player 2 (red)", "Player 3 (green)", "Player 4 (orange)"};
    const QPoint tiles[4] = {{scr.x(), scr.y()}, {scr.x() + tw, scr.y()},
                             {scr.x(), scr.y() + th}, {scr.x() + tw, scr.y() + th}};
    QList<Instance> insts;
    for (int i = 0; i < 4; ++i) {
        Instance in;
        in.name = QString("p%1").arg(i + 1);
        in.pos = tiles[i];
        in.size = QSize(tw, th);
        QGroupBox* box = new QGroupBox(labels[i]);
        QVBoxLayout* b = new QVBoxLayout(box);
        in.pad = new QComboBox;
        in.pad->addItem("(no gamepad)", QString());
        for (const auto& p : padPaths()) in.pad->addItem(padFriendly(p), p);
        QString saved = readConfPad(in.name);
        int idx = in.pad->findData(saved);
        if (idx >= 0) in.pad->setCurrentIndex(idx);
        in.toggle = new QPushButton("Launch");
        in.status = new QLabel("not running");
        b->addWidget(new QLabel("Gamepad:"));
        b->addWidget(in.pad);
        b->addWidget(in.toggle);
        b->addWidget(in.status);
        grid->addWidget(box, 0, i);
        insts << in;

        QObject::connect(in.toggle, &QPushButton::clicked, [i] { /* filled below */ });
    }
    v->addLayout(grid);

    // helper to refresh status labels
    QList<QLabel*> statusLabels;
    for (auto& in : insts) statusLabels << in.status;

    auto refresh = [&] {
        for (int i = 0; i < insts.size(); ++i) {
            qint64 pid = readPid(insts[i].name);
            if (alive(pid)) {
                insts[i].status->setText(QString("running (pid %1)").arg(pid));
                insts[i].toggle->setText("Stop");
            } else {
                insts[i].status->setText("not running");
                insts[i].toggle->setText("Launch");
            }
        }
        qint64 spid = [&] { QFile f(root() + "/server/pid"); if (!f.open(QIODevice::ReadOnly)) return -1LL; return f.readAll().trimmed().toLongLong(); }();
        serverState->setText(alive(spid) ? "server running" : "server stopped");
        serverBtn->setText(alive(spid) ? "Server: Stop" : "Server: Start");
    };

    auto tileWindow = [&](const Instance& in) {
        // position the SDL window once it exists (needs xdotool from setup-pc)
        QProcess::startDetached("/bin/sh", {
            "-c",
            QString("sleep 6; for W in $(xdotool search --pid %1 2>/dev/null); do "
                    "xdotool windowmove $W %2 %3; xdotool windowsize $W %4 %5; done")
                .arg(readPid(in.name)).arg(in.pos.x()).arg(in.pos.y())
                .arg(in.size.width()).arg(in.size.height())});
    };

    auto startOne = [&](int i) {
        Instance& in = insts[i];
        QString padPath = in.pad->currentData().toString();
        if (padPath.isEmpty()) {
            QMessageBox::warning(&win, "Pick a gamepad",
                                 QString("Player %1 has no gamepad selected.").arg(i + 1));
            return;
        }
        writeConf(in.name, padPath, in.size);
        QProcess::startDetached(root() + "/bin/mcpe-instance", {in.name});
        QTimer::singleShot(500, [&in, &tileWindow] { tileWindow(in); });
    };
    auto stopOne = [&](int i) {
        qint64 pid = readPid(insts[i].name);
        if (alive(pid)) QProcess::startDetached("/bin/kill", {QString::number(pid)});
    };

    for (int i = 0; i < insts.size(); ++i) {
        QObject::connect(insts[i].toggle, &QPushButton::clicked, [=] {
            if (alive(readPid(insts[i].name))) stopOne(i); else startOne(i);
            QTimer::singleShot(800, refresh);
        });
    }
    QObject::connect(startAll, &QPushButton::clicked, [&] {
        // server first (idempotent), then each instance staggered
        QProcess::startDetached("/bin/sh", {"-c",
            "[ -x " + root() + "/server/bedrock_server ] && { cd " + root() + "/server; "
            "if [ ! -f pid ] || ! kill -0 $(cat pid) 2>/dev/null; then "
            "setsid ./bedrock_server >> console.log 2>&1 & echo $! > pid; fi }"});
        QTimer::singleShot(1500, [&] { for (int i = 0; i < insts.size(); ++i) { startOne(i); } });
        QTimer::singleShot(6000, refresh);
    });
    QObject::connect(serverBtn, &QPushButton::clicked, [&] {
        QProcess::startDetached("/bin/sh", {"-c",
            "cd " + root() + "/server 2>/dev/null || exit; "
            "if [ -f pid ] && kill -0 $(cat pid) 2>/dev/null; then kill -INT $(cat pid); "
            "else setsid ./bedrock_server >> console.log 2>&1 & echo $! > pid; fi"});
        QTimer::singleShot(800, refresh);
    });

    QTimer* t = new QTimer(&win);
    QObject::connect(t, &QTimer::timeout, refresh);
    t->start(2000);
    refresh();
    win.resize(1100, 360);
    win.show();
    return app.exec();
}
