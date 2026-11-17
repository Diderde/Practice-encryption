# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""池占用扫描器（早期轮次 方法论机械化）：三判定合一，可重跑。

判定"池名已用"的证据源（三项齐算，缺一即漏判——0.0.5 的同仓碰撞即教训）：
  1) 跨项目基线：[日期略] 工作区实测（plus/era/meme 在 bili-dl 与
     Ryujin 的文档中被提及；保守口径计为已用，避免英文常用词误报为空闲）；
  2) 本仓历史：本仓全部 .py/.md 的词边界匹配——文档记载即占用（命名先于
     编码落盘，早期轮次 一类的历史条目与代码消费同权）；
  3) 自排除：verify 子命令只认扫描时刻的仓库现实；候选名在落盘前尚未写入
     任何文件，故天然不含自身——重跑时点为"写名前预检 + 提交前终检"
     （与工作区协作约定的计数自指纪律同源：判定动作不得污染判定对象）。

用法：
  python scripts/pool_scan.py                 # 打印 FREE_HEAD / USED_HEAD 与序号
  python scripts/pool_scan.py verify n1 n2 …  # 全部空闲退出 0，否则列出占用退出 1
"""
import os
import re
import sys
import unicodedata
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_EXCLUDE_DIRS = {".venv", ".git", "__pycache__", ".tmp", ".pytest_cache", "node_modules"}
# .rs/.c 入列：原生产物侧 native 源码同样消费命名池
_TEXT_EXT = {".py", ".md", ".rs", ".c"}

# 跨项目基线（整工作区扫描；只记文档提及的三个常用词）。
# 其余跨项目占用在"拉取全工作区复扫"时由 --scan-root 重新测定。
_BASELINE = {
    "plus": "bili-dl/README_EN.md（文档提及， 扫描）",
    "era": "Ryujin_obfuscation/CHANGES.md（文档提及， 扫描）",
    "meme": "Ryujin_obfuscation/研究报告.md（文档提及， 扫描）",
}

_CLASS_POOL_TEXT = """
Kasumi Toyama, Tae Hanazono, Rimi Ushigome, Saaya Yamabuki, Arisa Ichigaya,
Ran Mitake, Moca Aoba, Himari Uehara, Tomoe Udagawa, Tsugumi Hazawa,
Aya Maruyama, Hina Hikawa, Chisato Shirasagi, Maya Yamato, Eve Wakamiya,
Yukina Minato, Sayo Hikawa, Lisa Imai, Ako Udagawa, Rinko Shirokane,
Kokoro Tsurumaki, Kaoru Seta, Hagumi Kitazawa, Misaki Okusawa, Kanon Matsubara,
Mashiro Kurata, Touko Kirigaya, Nanami Hiromachi, Tsukushi Futaba, Rui Yashio,
Rei Wakana, Rokka Asahi, Masuki Satou, Reona Nyubara, Chiyu Tamade,
Tomori Takamatsu, Anon Chihaya, Rāna Kaname, Soyo Nagasaki, Taki Shiina,
Misumi Uika, Mutsumi Wakaba, Sakiko Togawa, Umiri Yahata, Nyamu Yutenji,
Arare Nakamachi, Nonoka Miyanaga, Ritsu Minetsuki, Miyako Fuji, Yuno Sengoku,
Asuka Toyama, Yuri Ushigome, Rii Uzawa, Hinako Nijikki, Nanana Wanibe
"""

# 562 名，取自工作区函数命名池全表（逐字一致）。
_FUNC_POOL_TEXT = """
Tokino Sora, Robocosan, Sakura Miko, Hoshimachi Suisei, AZKi,
Shirakami Fubuki, Natsuiro Matsuri, Akai Haato, Aki Rosenthal, Yozora Mel,
Hitomi Chris, Nakiri Ayame, Yuzuki Choco, Oozora Subaru, Minato Aqua,
Murasaki Shion, Ookami Mio, Nekomata Okayu, Inugami Korone, Usada Pekora,
Shiranui Flare, Shirogane Noel, Houshou Marine, Uruha Rushia, Tsunomaki Watame,
Tokoyami Towa, Himemori Luna, Kiryu Coco, Amane Kanata, Yukihana Lamy,
Momosuzu Nene, Shishiro Botan, Omaru Polka, Mano Aloe, La+ Darknesss,
Takane Lui, Hakui Koyori, Kazama Iroha, Sakamata Chloe, Otonose Kanade,
Ichijou Ririka, Juufuutei Raden, Todoroki Hajime, Hiodoshi Ao, Isaki Riona,
Koganei Niko, Mizumiya Su, Rindo Chihaya, Kikirara Vivi, Achichi Mela,
Sorashina Sopia, Suzuna Tsuzuri, Hyakuto Kyoko, Mori Calliope, Takanashi Kiara,
Ninomae Ina'nis, Watson Amelia, Gawr Gura, IRyS, Ouro Kronii,
Hakos Baelz, Tsukumo Sana, Ceres Fauna, Nanashi Mumei, Shiori Novella,
Nerissa Ravencroft, Koseki Bijou, Fuwawa Abyssgard, Mococo Abyssgard, Elizabeth Rose Bloodflame,
Gigi Murin, Cecilia Immergreen, Raora Panthera, Ayunda Risu, Moona Hoshinova,
Airani Iofifteen, Kureiji Ollie, Anya Melfissa, Pavolia Reine, Vestia Zeta,
Kaela Kovalskia, Kobo Kanaeru, Yogiri, Civia, Spade Echo,
Doris, Rosalyn, Artia, Kanade Izuru, Hanasaki Miyabi,
Rikka, Arurandeisu, Kagami Kira, Yakushiji Suzaku, Astel Leda,
Yukoku Roberu, Kishido Temma, Aragami Oga, Kageyama Shien, Tsukishita Kaoru,
Yatogami Fuma, Utsugi Uyu, Minase Rio, Hizaki Gamma, Regis Altare,
Axel Syrios, Magni Dezmond, Noir Vesper, Gavis Bettel, Machina X Flayon,
Banzoin Hakka, Josuiji Shinri, Jurard T Rexford, Goldbullet, Octavio,
Crimzon Ruze, Tsukino Mito, Shibuya Hajime, Higuchi Kaede, Shizuka Rin,
Moira, Elu, Yuki Chihiro, Suzuya Aki, Ienaga Mugi,
Mononobe Alice, Kenmochi Toya, Morinaka Kazaki, Fushimi Gaku, Gilzaren III,
Fumino Tamaki, Ushimi Ichigo, Yuuhi Riri, Suzuka Utako, Kanae,
Akabane Youko, Sasaki Saku, Honma Himawari, Makaino Ririmu, Kuzuha,
Shiina Yuika, Yamiyono Moruru, Setsuna, Dola, Hanabatake Chaika,
Ryushen, Sister Claire, Suzuki Masaru, Todoroki Kyoko, Uzuki Kou,
Yashiro Kizuku, Nakao Azuma, Umiyashano Kami, Hassaku Yuzu, Izumo Kasumi,
Azuchi Momo, Harusaki Air, Kanda Shoichi, Amemori Sayo, Takamiya Rion,
Asuka Hina, Maimoto Keisuke, Debidebi Debiru, Rindou Mikoto, Joe Rikiichi,
Machita Chima, Sakura Ritsuki, Belmond Banderas, Yaguruma Rine, Yumeoi Kakeru,
Kuroi Shiba, Naruto Kogane, Tsukimi Shizuku, Achikita Chinami, Naruse Naru,
Kudo Chitose, Warabeda Meiji, Yuzuki Roa, Gundo Mirei, Onomachi Haruka,
Kataribe Tsumugu, Seto Miyako, Shindo Raito, Otogibara Era, Inui Toko,
Ange Katrina, Lize Helesta, Saegusa Akina, Aizono Manami, Yukishiro Mahiro,
Suzuhara Lulu, Ex Albio, Levi Elipha, Hayama Marin, Nui Sociere,
Hakase Fuyuki, Yorumi Rena, Kagami Hayato, Ars Almal, Mayuzumi Kai,
Aiba Uiha, Amamiya Kokoro, Eli Conifer, Ratna Petit, Sukoya Kana,
Hayase Sou, Shellin Burgundy, Fumi, Yamagami Karuta, Hoshikawa Sara,
Emma★August, Luis Cammy, Matsukai Mao, Shirayuki Tomoe, Fuwa Minato,
Gwelu Os Gar, Kurusu Natsume, Mashiro Meme, Naraka, Furen E Lustario,
Ibrahim, Melissa Kinrenka, Genzuki Tojiro, Nagao Kei, Kaida Haru,
Sorahoshi Kirame, Kingyozaka Meiro, Suo Sango, Kitakoji Hisui, Todo Kohaku,
Nishizono Chigusa, Asahina Akane, Lauren Iroas, Leos Vincent, Oliver Evans,
Lain Paterson, Axia Krone, Umise Yotsuha, Amagase Muyu, Ponto Nei,
Hyakumantenbara Salome, Fura Kanato, Watarai Hibari, Shikinagi Akira, Seraph Dazzlegarden,
Igarashi Rika, Koshimizu Toru, Ishigami Nozomi, Sophia Valentine, Kuramochi Meruto,
Kaburaki Roco, Shishido Akari, Akagi Wen, Usami Rito, Hibachi Mana,
Saiki Ittetsu, Murakumo Kagetsu, Hoshirube Sho, Koyanagi Rou, Inami Rai,
Tachitsute Toto, Shioriha Ruri, Milan Kestrel, Kitami Yusei, Kaisei,
Sakaki Ness, Shiga Riko, Tamanoi Nana, Kisara, Kozue Mone,
Lunlun, Nanase Suzuna, Saotome Berry, Kirara Tamako, Sakayori Soma,
Nagisa Trout, Hitotsubashi Ayato, Itsuki Sakyo, Kadou Mikaru, Yagyu Shino,
Togawa Nonoha, Nekoyashiki Miku, Sumeragi Reo, Shinomiya Yuno, Shirose Isumi,
Hanakago Tsubasa, Shirasu Ayane, Minamo Madoka, Rei7, Onotora,
Elira Pendora, Finana Ryugu, Pomu Rainpuff, Petra Gurin, Selen Tatsuki,
Rosemi Lovelock, Millie Parfait, Enna Alouette, Nina Kosaka, Reimu Endou,
Luca Kaneshiro, Shu Yamino, Vox Akuma, Mysta Rias, Ike Eveland,
Sonny Brisko, Uki Violeta, Alban Knox, Fulgur Ovid, Yugo Asuma,
Maria Marionette, Aia Amare, Scarle Yonaguni, Ren Zotto, Kyo Kaneko,
Aster Arcadia, Doppio Dropscythe, Meloco Kyoran, Ver Vermillion, Kotoka Torahime,
Hex Haywire, Zaion LanZa, Vezalius Bandage, Vantacrow Bringer, Yu Q. Wilson,
Colin Clawmark, Kunai Nakasato, Victoria Brightshield, Ryoma Barrenwort, Klara Charmwood,
Twisty Amanozako, Zeal Ginjoka, Freodore, Seible, Kaelix Debonair,
Aadya, Noor, Vihaan, Hana Macchia, ZEA Cornelia,
Taka Radjiman, Rai Galilei, Amicia Michella, Miyu Ottavia, Riksa Dhirendra,
Layla Alstroemeria, Azura Cecillia, Nara Haramaung, Etna Crimson, Siska Leontyne,
Bonnivier Pranaja, Nagisa Arcinia, Derem Kado, Reza Avanluna, Hyona Elatiora,
Xia Ekavira, Mika Melatika, Min Suha, Yu Ruri, Wiffy,
Shin Yuya, Gaon, Han Chiho, Kaen, Moarin,
Lorou, Hakuren, So Nagi, Lee Siu, Chae Ara,
Lee Roha, Akira Ray, Nun Bora, Yang Nari, Ryu Hari,
Oh Jiyu, Shin Kiru, Seffyna, Song Mia, Ban Hada,
Na Sera, Ha Yun, Ko Yami, Lee On, Kurohane Kuroto,
Kaminari Poaro, Tenkai Tsukasa, Fairys-chan, Yingou, Siddel,
Limaoshan, Miyashita Mariko, Angie Fei, Royuanan, Qing,
Saitania Liun Limse, Monmon, Atles, Dailechi, Chen Kuang Kuang,
Kobayakawa Nana, Mifentan, Siarurin, Talency, Eine,
Ruki, Nana7mi, Kouichi, Ichigo, Hanon,
Muri, Wakuhime, Nyatsuki, Plus, Hoshimi,
Mahiru, Miki, Yagi Michiyuki, Tabibito, Aza,
Roi Eineberg, Momose Yukie, Saya, Yononaka Seiya, Mimoi,
Pax, Samael, Shiki, Karu, Wakatsuki Chiharu,
Chaos, Kiyora, Shaun, Yua, Sirius,
Reve Iris, Chiyuu, Tanoshi, Imi, Mari,
Mayumi, Tsukumo, Remi, Kendou, Tocci,
Joi, Kiti, Qilou, Rhea, Hakuja,
Yomiya, Koxia, Miyu, Hunger, Yog,
Uka, Keke, Sybil, Girimi, Kiyuu,
Karisa, Leo, Sui, Era, Eve,
Opal, Shiori, Hatsuse, Ameki, Michiya,
Awu, Irifuku Ayumi, Usagigawa Mizuki, Richi, Mikoto,
Urushiha, Hajime, Kurau, Garu, Pako,
Nagisa, Yukisyo, Hihi, Kima, Inochi,
Harei, Susu, Midorigawa Momoka, Melody, Mei,
Meme, Mit3uri, Nimue, Kioi, Nori,
Mofu, Nanako, Aria Zuyanaxi, Sakura Haruka, Ureme,
Lingyuan yousa, hanser, Andou Inari, KINGSK, Mitsusa,
Sumire Hina, Suzuka, Mama Mara, Prime Star, Karon,
Isabella, Azusa, Rin Miyazono, Kero, Syo,
Ruruna, Mori, Jinxy, Susam, Noi,
Nox, Bekki, Lian, Queenie, Yoyi,
Kaga Sumire, Kaga Nazuna, Kogara Toto, Ichinose Uruha, Kurumi Noah,
Tosaki Mimi, Sena Asumi, Tachibana Hinano, Hanabusa Lisa, Kisaragi Ren,
Kaminari Qpi, Yakumo Beni, Aizawa Ema, Shinomiya Runa, Nekota Tsuna,
Shiranami Ramune, Komori Met, Yumeno Akari, Yano Kuromu, Tsumugi Kokage,
Sendo Yuuhi, Choya Hanabi, Amayui Moka, Ginjo Saine, Tatsumaki Chise,
Remia Aotsuki, Arya Kuroha, Jira Jisaki, Narin Mikure, Riko Solari,
Eris Suzukami, Juno Umezono, Kohari Aya, Shirasaki Tsuyuri, Pafi,
Sen, Hinata Haru
"""

_SEP_CHARS = {"★", "+", "-", ".", "·"}


def inugami_korone():
    """按手册原文转换规则程序化生成两池标识符：返回 (类池列表, 函数池列表)。

    函数名：空格/分隔符（★ + - .）→ 下划线；撇号移除；非 ASCII 降 ASCII；
    各段小写后下划线连接。类名：空格移除、各段首字母大写连接。
    （文档样例逐条对齐：AZKi→azki、IRyS→irys、Emma★August→emma_august、
    Ninomae Ina'nis→ninomae_inanis、Yu Q. Wilson→yu_q_wilson、Rāna Kaname→RanaKaname。）"""

    def ascii_fold(text):
        decomposed = unicodedata.normalize("NFKD", text)
        return "".join(ch for ch in decomposed if not unicodedata.combining(ch))

    def to_func_name(raw):
        folded = ascii_fold(raw.strip())
        parts = []
        cur = ""
        for ch in folded:
            if ch.isspace() or ch in _SEP_CHARS:
                if cur:
                    parts.append(cur)
                cur = ""
            elif ch == "'":
                continue
            else:
                cur += ch
        if cur:
            parts.append(cur)
        return "_".join(p.lower() for p in parts)

    def to_class_name(raw):
        folded = ascii_fold(raw.strip())
        return "".join(p[:1].upper() + p[1:] for p in folded.split())

    def parse_pool(text):
        items = []
        for chunk in text.replace("\n", ",").split(","):
            name = chunk.strip()
            if name:
                items.append(name)
        return items

    classes = [to_class_name(n) for n in parse_pool(_CLASS_POOL_TEXT)]
    funcs = [to_func_name(n) for n in parse_pool(_FUNC_POOL_TEXT)]
    if len(classes) != 55 or len(funcs) != 562:
        raise AssertionError(f"pool size drift: classes={len(classes)} funcs={len(funcs)}")
    return classes, funcs


def suzuna_tsuzuri():
    """扫描本仓：返回 {名字: 首个证据位置}；词边界全词匹配，.py/.md 同权。

    遍历用 os.walk 且对 reparse point（junction/符号链接）剪枝——rglob 会
    跟随 junction 走进目标子树（实例：测试残留的 Lib junction → 全 stdlib
    重扫，分钟级挂起）。"""
    files = []
    for root, dirs, names in os.walk(_REPO):
        dirs[:] = [d for d in dirs
                   if d not in _EXCLUDE_DIRS
                   and not (os.path.lexists(os.path.join(root, d))
                            and os.lstat(os.path.join(root, d)).st_file_attributes & 0x400)]
        for name in names:
            path = Path(root) / name
            if path.suffix.lower() not in _TEXT_EXT:
                continue
            files.append(path)
    texts = [(p.relative_to(_REPO).as_posix(), p.read_text(encoding="utf-8", errors="replace")) for p in files]
    global _SCAN_TEXTS
    _SCAN_TEXTS = [(rel, t) for rel, t in texts if rel.endswith(".py")]
    usage = {}
    _, funcs = inugami_korone()
    for idx, ident in enumerate(funcs, start=1):
        pattern = re.compile(r"\b" + re.escape(ident) + r"\b")
        for rel, text in texts:
            hit = pattern.search(text)
            if hit:
                line = text.count("\n", 0, hit.start()) + 1
                usage[ident] = f"#{idx} {rel}:{line}"
                break
    for ident, where in _BASELINE.items():
        usage.setdefault(ident, f"#? {where}")
    return usage


def mococo_abyssgard(argv=None):
    """入口：无参打印 FREE_HEAD/USED_HEAD 汇总；verify 子命令校验候选名全部空闲。"""
    classes, funcs = inugami_korone()
    usage = suzuna_tsuzuri()
    if argv and argv[0] == "verify":
        conflicts = [n for n in argv[1:] if n in usage]
        if conflicts:
            for n in conflicts:
                print(f"USED: {n} -> {usage[n]}")
            return 1
        print(f"verify ok: {len(argv) - 1} name(s) free")
        return 0
    free = [n for n in funcs if n not in usage]
    used_funcs = [n for n in funcs if n in usage]
    print(f"function pool: {len(funcs)} names, {len(used_funcs)} used, {len(free)} free")
    print("FREE_HEAD:")
    for i, n in enumerate(free[:24]):
        idx = funcs.index(n) + 1
        print(f"  #{idx} {n}")
    print("USED_HEAD:")
    for n in used_funcs[:8]:
        print(f"  {usage[n]}")
    class_used = [c for c in classes if re.search(r"\b" + re.escape(c) + r"\b", " ".join(
        t for _, t in _SCAN_TEXTS))]
    print(f"class pool free head: {[c for c in classes if c not in class_used][:8]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(mococo_abyssgard(sys.argv[1:]))
