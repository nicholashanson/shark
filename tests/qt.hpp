#ifndef QT_HPP
#define QT_HPP

#include <QApplication>
#include <QMediaPlayer>
#include <QVideoWidget>
#include <QTemporaryFile>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>
#include <QLabel>
#include <QPixmap>
#include <QDir>
#include <QFile>
#include <QUrl>

#include <vector>
#include <cstdint>
#include <fstream>

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

    inline void show_mp4_in_qt_window( const std::vector<uint8_t>& mp4_data ) {

        int argc = 0;
        char** argv = nullptr;
        QApplication app( argc, argv );

        // Write MP4 data to a temporary file
        QTemporaryFile temp_file( QDir::tempPath() + "/color.mp4" );
        temp_file.setAutoRemove( false );
        if ( !temp_file.open() ) {
            QLabel label( "Failed to create temp video file." );
            label.setWindowTitle( "MP4 Viewer - Error" );
            label.resize( 400, 100 );
            label.show();
            QTimer::singleShot( 3000, &app, &QApplication::quit );
            app.exec();
            return;
        }

        temp_file.write( reinterpret_cast<const char*>( mp4_data.data()), mp4_data.size() );
        QString temp_file_path = temp_file.fileName();
        temp_file.close();

        // Create media player and video widget
        QMediaPlayer* player = new QMediaPlayer;
        QVideoWidget* video_widget = new QVideoWidget;

        QWidget window;
        QVBoxLayout* layout = new QVBoxLayout;
        layout->addWidget( video_widget );
        window.setLayout(layout);
        window.setWindowTitle("MP4 Viewer");
        window.resize(640, 480);

        player->setVideoOutput( video_widget );
        player->setMedia(QUrl::fromLocalFile(temp_file_path));
        player->play();

        window.show();

        // Automatically quit after video duration or fallback timer
        QObject::connect( player, &QMediaPlayer::mediaStatusChanged, [&]( QMediaPlayer::MediaStatus status ) {
            if ( status == QMediaPlayer::EndOfMedia || status == QMediaPlayer::InvalidMedia ) {
                app.quit();
            }
        });

        QTimer::singleShot( 30000, &app, &QApplication::quit ); // Fallback timeout

        app.exec();

        QFile::remove( temp_file_path ); // Clean up
    }

} // test

#endif
