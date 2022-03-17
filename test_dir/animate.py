import sys
from PyQt5.Qt import *


class Window(QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setWindowTitle('Анимация')
        self.resize(500, 500)
        self.move(400, 200)
        self.btn = QPushButton(self)
        self.init_ui()

    def init_ui(self):
        self.btn.resize(100, 100)
        self.btn.move(0, 0)
        self.btn.setStyleSheet('QPushButton{border: none; background: pink;}')

        # 1. Определите анимацию
        animation = QPropertyAnimation(self)
        animation.setTargetObject(self.btn)
        animation.setPropertyName(b'pos')
        # Используйте другой метод конструктора для создания
        # animation = QPropertyAnimation(self.btn, b'pos', self)

        # 2. Установите значение атрибута
        animation.setStartValue(QPoint(0, 0))
        animation.setEndValue(QPoint(400, 400))

        # 3. Установите продолжительность
        animation.setDuration(3000)

        # 4. Запустить анимацию
        animation.start()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Window()
    window.show()
    sys.exit(app.exec_())