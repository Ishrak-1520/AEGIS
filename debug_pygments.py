from pygments.lexers import guess_lexer
from pygments.util import ClassNotFound

samples = [
    ("Python", "def hello():\n    print('Hello World')"),
    ("Python Long", "import os\n\ndef main():\n    print('Hello')\n\nif __name__ == '__main__':\n    main()"),
    ("JS", "function hello() { console.log('Hello World'); }"),
    ("JS Long", "const x = 10;\nfunction test() {\n  return x * 2;\n}\nconsole.log(test());"),
]

for name, code in samples:
    try:
        lexer = guess_lexer(code)
        print(f"Sample '{name}': {lexer.name}")
    except ClassNotFound:
        print(f"Sample '{name}': ClassNotFound")
    except Exception as e:
        print(f"Sample '{name}': Error {e}")
