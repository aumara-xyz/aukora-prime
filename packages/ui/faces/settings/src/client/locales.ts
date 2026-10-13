/** Shell chrome and General-nav dictionaries; feature rows own their copy. */

/** Simplified Chinese dictionary (the key-set source of truth). */
export const zh = {
  'title': '设置',
  'close': '关闭',
  'openDocument': '打开配置文件',
  'openDocument.error': '无法打开配置文件',
  'general.nav': '通用设置',
  'general.menuDescription': '语言、外观与默认选项',
  'aura.trigger': 'Aura Coherence',
  'aura.subtitle': '记录的当前快照',
  'aura.close': '关闭',
  'aura.status.rest': '实态 · 记录头的精确图形',
  'aura.status.moving': '运动中 · 过渡帧，不是记录状态',
  'aura.figure.title': 'Aura 快照的 Pentora',
  'aura.figure.description': '固定五立方体与 110 个三进制格，来自显示域和快照头的 SHA-256。',
  'aura.snapshot.head': '快照头',
  'aura.snapshot.entries': '打开后观察到 {count} 个源记录前进',
  'aura.snapshot.present': '{count} / 3 个源提供了头',
  'aura.snapshot.absent': '缺失',
  'aura.snapshot.available': '已提供',
  'aura.snapshot.records': '条记录',
  'aura.activity.title': '最近观察到的前进',
  'aura.snapshot.details': '完整头与快照输入',
  'aura.snapshot.waiting': '等待记录头；尚无图形。',
  'aura.snapshot.stale': '读取失败；图形仅表示上次观察到的快照',
  'aura.snapshot.meaning': '两个人或两台设备看到相同 Pentora，即持有相同记录快照的显示指纹。可在详情比较完整头。',
  'aura.snapshot.limit': '图形不证明记录完整、身份、谁在观看或审批。未暴露的头不是空链。',
  'aura.snapshot.polling': '可见时每两秒读取一次，可能跳过中间头。三个源分别标识门审批账本、Kira 记忆账本和当前版本的记录（一个记录）。缺失的源会明确显示。',

  'aura.menu': '记录快照',
} satisfies Record<string, string>

/** The settings namespace key union. */
export type SettingsKey = keyof typeof zh

/** English dictionary, checked complete against the zh key set. */
export const en = {
  'title': 'Settings',
  'close': 'Close',
  'openDocument': 'Open configuration file',
  'openDocument.error': 'Could not open configuration file',
  'general.nav': 'General',
  'general.menuDescription': 'language, appearance, and defaults',
  'aura.trigger': 'Aura Coherence',
  'aura.subtitle': 'Current snapshot of the record',
  'aura.close': 'Close',
  'aura.status.rest': 'Solid · exact snapshot-head picture',
  'aura.status.moving': 'In motion · transition, not a recorded state',
  'aura.figure.title': 'Pentora of the Aura snapshot',
  'aura.figure.description': 'Five fixed cubes and 110 ternary cells from SHA-256 of the display domain and snapshot head.',
  'aura.snapshot.head': 'Snapshot head',
  'aura.snapshot.entries': '{count} observed source entries advanced since opening',
  'aura.snapshot.present': '{count} / 3 sources supplied a head',
  'aura.snapshot.absent': 'Absent',
  'aura.snapshot.available': 'Present',
  'aura.snapshot.records': 'entries',
  'aura.activity.title': 'Recently observed advances',
  'aura.snapshot.details': 'Full heads and snapshot inputs',
  'aura.snapshot.waiting': 'Waiting for recorded heads; no picture yet.',
  'aura.snapshot.stale': 'Read failed; the picture shows only the last observed snapshot',
  'aura.snapshot.meaning': 'Two people or devices seeing the same Pentora hold the same displayed snapshot fingerprint of the record. Compare full heads under Details.',
  'aura.snapshot.limit': 'The picture does not prove completeness, identity, who is looking, or approval. A head not exposed is not an empty chain.',
  'aura.snapshot.polling': 'Reads every two seconds while visible; intermediate heads may be missed. The three sources identify gate approvals, Kira memory and the running release record (one record). Missing sources remain explicit.',

  'aura.menu': 'record snapshot',
} satisfies Record<SettingsKey, string>
