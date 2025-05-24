#ifndef QT_HPP
#define QT_HPP

#include <QApplication>
#include <QLabel>
#include <QString>
#include <QTimer>

namespace test {

    inline void show_text_in_qt_window( const QString& text ) {

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

    inline void show_bitmap_in_qt_window( const std::vector<uint8_t>& bmp_data ) {

        int argc = 0;
        char** argv = nullptr;
        QApplication app( argc, argv );

        QImage image = QImage::fromData( reinterpret_cast<const uchar*>( bmp_data.data() ), bmp_data.size(), "BMP" );

        if ( image.isNull() ) {
            QLabel label( "Failed to load image." );
            label.setWindowTitle( "Bitmap Viewer - Error" );
            label.resize( 400, 100 );
            label.show();
            QTimer::singleShot( 3000, &app, &QApplication::quit );
            app.exec();
            return;
        }

        QLabel label;
        label.setPixmap( QPixmap::fromImage( image ) );
        label.setWindowTitle( "Bitmap Viewer" );
        label.resize( image.width() * 4, image.height() * 4 );
        label.show();

        QTimer::singleShot( 3000, &app, &QApplication::quit );
        app.exec();
    }

} // test

#endif
