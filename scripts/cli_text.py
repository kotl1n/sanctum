"""Русская справка и сообщения CLI; служебные поля JSON остаются стабильными."""

import argparse
import json
import sys


class ArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        add_help = kwargs.pop('add_help', True)
        super().__init__(*args, add_help=False, **kwargs)
        self._positionals.title = 'Аргументы'
        self._optionals.title = 'Параметры'
        if add_help:
            self.add_argument('-h', '--help', action='help', help='Показать справку и выйти')

    def add_subparsers(self, **kwargs):
        kwargs.setdefault('title', 'Команды')
        kwargs.setdefault('metavar', 'КОМАНДА')
        return super().add_subparsers(**kwargs)

    def format_usage(self):
        return super().format_usage().replace('usage: ', 'Использование: ', 1)

    def format_help(self):
        return super().format_help().replace('usage: ', 'Использование: ', 1)

    def error(self, message):
        # Не включаем пользовательские аргументы в диагностику: в них могут быть секреты.
        self.print_usage(sys.stderr)
        self.exit(2, f'{self.prog}: ошибка в аргументах. Подробности: --help.\n')


def print_result(result):
    output = dict(result)
    messages = {
        'plan': 'План подготовлен. Изменения ещё не применены.',
        'staged': 'Файлы подготовлены. Перезапустите Desktop через Sanctum.',
        'saved': 'Настройки сохранены. Перезапустите Desktop через Sanctum.',
        'removed': 'Установленные файлы удалены; изменённые настройки сохранены.',
        'restored': 'Транзакция отменена. Перезапустите Desktop через Sanctum.',
        'recovered': 'Восстановление прерванных операций завершено.',
        'error': 'Операция не выполнена. Служебный код указан в поле reason.',
    }
    if output.get('status') in messages:
        output['message'] = messages[output['status']]
    elif 'compatible' in output:
        output['message'] = ('Совместимость подтверждена.' if output['compatible']
                             else 'Совместимость не подтверждена. Причины указаны в поле reasons.')
    elif 'backends' in output:
        output['message'] = 'Доступные версии серверной части.'
    print(json.dumps(output, ensure_ascii=False))
