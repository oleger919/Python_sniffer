import sys
import random  # +++
from datetime import datetime
from PyQt5.QtWidgets import QApplication, QMainWindow, QGridLayout, QWidget, \
    QTableWidget, QTableWidgetItem
from PyQt5.QtCore import QSize, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont


class DataParser(QThread):
    data_signal = pyqtSignal(list)

    def __init__(self):
        super(DataParser, self).__init__()
        self._date = ''
        self._nameProg = ''
        self._start = ''
        self._flag = True

    def run(self):
        self.msleep(2000)
        # вставьте в этот цикл свою логику получения списка list_to_add
        # у меня это рандомный _list, который формируется каждые 10 секунд,
        # чтобы вы спокойно могли наблюдать что происходит
        while (self._flag):
            #             '2021-02-02 09:00:00' обратите внимание я поменял дату
            self._date = f'2021-02-03 {random.randrange(0, 24):0>2}:' \
                         f'{random.randrange(0, 60):0>2}:' \
                         f'{random.randrange(0, 60):0>2}'
            self._nameProg = f'PROGRAM {random.randrange(1, 99):0>2}'
            self._start = 'Что-то еще?'

            _list = [self._date, self._nameProg, self._start]
            self.data_signal.emit(_list)  # отдаем список в основной поток
            self.msleep(10000)  # спим 10 секунд


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setMinimumSize(QSize(480, 100))
        self.setWindowTitle("Работа с QTableWidget")
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        grid_layout = QGridLayout(central_widget)  # - self  --> + central_widget !!!
        #        central_widget.setLayout(grid_layout)            # --- нет

        self.tableWidget = QTableWidget(self)
        header_font = QFont('Sergoe UI', 12)
        header_font.setWeight(QFont.Bold)

        self.tableWidget.setColumnCount(4)  # (3) обратите внимание я добавил столбец

        self.tableWidget.setHorizontalHeaderLabels(
            ["Относительное время", "Абсолютное время", "Название операции"]
        )
        self.tableWidget.horizontalHeaderItem(0).setFont(header_font)
        self.tableWidget.horizontalHeaderItem(1).setFont(header_font)
        self.tableWidget.horizontalHeaderItem(2).setFont(header_font)
        self.tableWidget.setColumnWidth(0, 190)  # 250
        self.tableWidget.setColumnWidth(1, 180)  # 250
        self.tableWidget.setColumnWidth(2, 180)  # 250
        self.tableWidget.setColumnWidth(3, 180)  # обратите внимание я добавил столбец

        # ВНИМАНИЕ !!! раскомментируйте строку ниже, чтобы Скрыть столбец с индексом 3       !!!
        #        self.tableWidget.setColumnHidden(3, True)   # Скрыть столбец с индексом 3  !!!

        #        list_to_add = ['2021-02-03 09:00:00', 'PROGRAM', 'START'] # обратите внимание я поменял дату
        list_to_add = ['2021-02-03 17:20:00', 'PROGRAM', 'START']  # !!!

        rowPos = self.tableWidget.rowCount()
        time_abs = self.time_abs_func(list_to_add)
        # -        print(f'time_abs = {time_abs}')

        self.tableWidget.insertRow(rowPos)

        self.tableWidget.setItem(rowPos, 1, QTableWidgetItem(time_abs))
        self.tableWidget.setItem(rowPos, 2, QTableWidgetItem(list_to_add[1]))
        # обратите внимание я добавил столбец vvv                               !!!
        self.tableWidget.setItem(rowPos, 3, QTableWidgetItem(list_to_add[0]))

        # grid_layout.addWidget(table, 0, 0)                   # Adding the table to the grid
        grid_layout.addWidget(self.tableWidget, 0, 0)  # +++ !!!

        # +++ vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
        self.thread = DataParser()
        self.thread.data_signal.connect(self.update_data)
        self.thread.start()

    def time_abs_func(self, list_to_add):
        date_now = datetime.now()
        datetime_event = datetime.strptime(list_to_add[0], '%Y-%m-%d %H:%M:%S')
        delta_sec = (datetime.now() - datetime_event).total_seconds()
        return self.convert_sec_to_time(delta_sec)

    def convert_sec_to_time(self, seconds) -> str:
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return '{:02}:{:02}:{:02}'.format(int(hours), int(minutes), int(seconds))

    def update_data(self, _data):
        """ Тут мы добавляем новую запись в таблицу
            и динамически обновляем значения в таблице.
            _data - это полученный из класса DataParser - list_to_add
        """
        time_abs = self.time_abs_func(_data)

        #        rowPos = self.tableWidget.rowCount()         # добавить в конец
        rowPos = 0  # добавить в начало

        # добавляем новую запись
        self.tableWidget.insertRow(rowPos)
        self.tableWidget.setItem(rowPos, 1, QTableWidgetItem(time_abs))
        self.tableWidget.setItem(rowPos, 2, QTableWidgetItem(_data[1]))
        self.tableWidget.setItem(rowPos, 3, QTableWidgetItem(_data[0]))  # !!!

        # обновляем значения в таблице
        rows = self.tableWidget.rowCount()

        #        for row in range(0, rows-1):                 # для rowPos = self.tableWidget.rowCount()
        for row in range(1, rows):  # для rowPos = 0
            _data = self.tableWidget.item(row, 3).text()
            time_abs = self.time_abs_func([_data, ])
            # обратите внимание, что я вставляю обновленные данные               !!!
            # в колонку с индексом 0 (ноль) - чтобы вы видели, что происходит    !!!
            self.tableWidget.setItem(row, 0, QTableWidgetItem(time_abs))


#            self.tableWidget.setItem(row, 1, QTableWidgetItem(time_abs))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Times", 10, QFont.Bold))
    mw = MainWindow()
    mw.resize(810, 500)
    mw.show()
    sys.exit(app.exec_())