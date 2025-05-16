#include <QApplication>
#include <QLabel>
#include <QString>
#include <QTimer>

namespace test {

    void show_text_in_qt_window( const QString& text ) {

        int argc = 0;
        char** argv = nullptr;
        
        QApplication app( argc, argv );

        QLabel label(text);

        label.setWindowTitle( "Packet Parsing Visual Test" );
        label.resize( 400, 200 );
        label.show();

        QTimer::singleShot( 3000, &app, &QApplication::quit );

        app.exec();
    }

}
