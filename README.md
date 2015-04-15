# kwzrhouse API

## 特徴
- @kvvzr の家を自由に操作できる
- でも自由に操作されると困るので認証をつける
- なんも考えてない

## 起動方法

```
$ git clone https://github.com/kwzrhouse/api.kwzrhouse.net
$ pip install -r requirements.txt

# [Twitter Apps](https://apps.twitter.com/)を登録して, Consumer KeyとConsumer Secretをconfig.pyに書く
# Callback URLを`http://localhost:5000`に設定する

$ python app.py
```

## やっておくといいこと

```
$ git update-index --skip-worktree config.py
```
