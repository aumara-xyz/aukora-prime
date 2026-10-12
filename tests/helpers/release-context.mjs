// Record plugin effects and refuse undeclared service property reads.
export function normalizedPlugin(namespace) {
  let plugin = namespace?.default ?? namespace
  if (plugin?.__esModule) plugin = plugin.default ?? plugin
  return plugin
}

export function requiredInject(plugin) {
  const declaration = plugin?.inject
  return Array.isArray(declaration) ? [...declaration] : Object.keys(declaration ?? {})
}

export function strictContext(inject, services = {}, options = {}) {
  const store = new Map(services instanceof Map ? services : Object.entries(services))
  const refusals = [], pending = [], disposers = [], logs = [], failures = [], registrations = []
  const handlers = new Map(), accessors = new Map()
  let drained = 0, disposed = false, root

  function tracked(promise) {
    const task = Promise.resolve(promise).catch(error => { failures.push(error) })
    pending.push(task)
    return task
  }

  function logger() {
    return log
  }
  const log = Object.fromEntries(['info', 'warn', 'error', 'debug'].map(level => [level, (...args) => {
    logs.push(args.map(value => value instanceof Error ? value.message : String(value)).join(' '))
    options.logger?.[level]?.(...args)
  }]))
  Object.assign(logger, log)

  function effect(create) {
    const cleanup = []
    let setup, released = false
    const collect = value => {
      if (value == null) return
      if (typeof value === 'function') { cleanup.push(value); return }
      throw new TypeError('Invalid effect')
    }
    const consume = value => {
      if (value == null || typeof value === 'function') return collect(value)
      if (typeof value.then === 'function') return Promise.resolve(value).then(collect)
      if (typeof value[Symbol.iterator] === 'function') { for (const dispose of value) collect(dispose); return }
      if (typeof value[Symbol.asyncIterator] === 'function') return (async () => { for await (const dispose of value) collect(dispose) })()
      throw new TypeError('Invalid effect')
    }
    const release = async () => {
      if (released) return
      released = true
      if (setup) await setup
      for (const dispose of cleanup.splice(0).reverse()) await dispose()
    }
    disposers.push(release)
    try { setup = consume(create()) }
    catch (error) { failures.push(error); throw error }
    if (setup) tracked(setup)
    const wrapper = () => release()
    wrapper.then = (resolve, reject) => Promise.resolve(setup).then(() => release).then(resolve, reject)
    return wrapper
  }

  function eventArgs(args) {
    const index = args.findIndex(value => typeof value === 'string')
    return { name: args[index], args: args.slice(index + 1) }
  }

  function buildContext(declared, meta = {}, parent) {
    const owned = new Set()
    const target = Object.assign(Object.create(parent ?? null), meta)
    let ctx
    const get = name => store.get(name)
    const provide = (name, value) => effect(() => {
      if (store.has(name)) throw new Error(`service "${name}" has been registered`)
      store.set(name, value)
      owned.add(name)
      return () => { store.delete(name); owned.delete(name) }
    })
    const set = (name, value) => {
      if (!owned.has(name)) throw new Error(`cannot set property "${name}" without provide`)
      store.set(name, value)
    }
    const on = (name, callback) => effect(() => {
      const listeners = handlers.get(name) ?? new Set()
      handlers.set(name, listeners)
      listeners.add(callback)
      return () => listeners.delete(callback)
    })
    const once = (name, callback) => {
      let dispose
      dispose = on(name, (...args) => { void dispose(); return callback(...args) })
      return dispose
    }
    const listeners = args => {
      const event = eventArgs(args)
      return [...(handlers.get(event.name) ?? [])].map(callback => () => callback(...event.args))
    }
    const emit = (...args) => {
      for (const callback of listeners(args)) {
        const value = callback()
        if (value && typeof value.then === 'function') tracked(value)
      }
    }
    const parallel = (...args) => Promise.all(listeners(args).map(callback => callback()))
    const serial = async (...args) => {
      for (const callback of listeners(args)) { const value = await callback(); if (value != null && value !== false) return value }
    }
    const bail = (...args) => {
      for (const callback of listeners(args)) { const value = callback(); if (value != null && value !== false) return value }
    }
    const waterfall = (...args) => {
      const event = eventArgs(args)
      let value = event.args[0]
      for (const callback of handlers.get(event.name) ?? []) value = callback(value, ...event.args.slice(1))
      return value
    }
    const accessor = (name, definition) => effect(() => {
      if (accessors.has(name) || store.has(name)) throw new Error(`property "${name}" is already declared`)
      accessors.set(name, definition)
      return () => accessors.delete(name)
    })
    const mixin = (source, keys) => {
      const entries = Array.isArray(keys) ? keys.map(key => [key, key]) : Object.entries(keys)
      return effect(function* () {
        for (const [key, name] of entries) yield accessor(name, {
          get() {
            const service = typeof source === 'string' ? ctx[source] : source
            const value = service?.[key]
            return typeof value === 'function' ? value.bind(service) : value
          },
        })
      })
    }
    const plugin = (candidate, config) => {
      const selected = normalizedPlugin(candidate)
      registrations.push({ plugin: selected, config })
      let setup = Promise.resolve(), cleanup = []
      const fiber = { dispose: async () => {
        await setup
        for (const dispose of cleanup.splice(0).reverse()) await dispose()
      }, name: selected?.name, await: () => setup }
      if (options.runPlugins) {
        const deps = requiredInject(selected)
        if (deps.every(name => store.get(name) !== undefined)) {
          const child = buildContext(new Set([...declared, ...deps]), {}, target)
          setup = Promise.resolve().then(async () => {
            if (selected.Config?.['~standard']) {
              const result = await selected.Config['~standard'].validate(config)
              if (result.issues) throw new Error('release-context:config-invalid')
              config = result.value
            }
            const offset = disposers.length
            if (typeof selected === 'function' && selected.prototype
              && !['GeneratorFunction', 'AsyncGeneratorFunction'].includes(selected.constructor.name)) {
              const instance = new selected(child, config)
              for (const hook of instance?.[Symbol.for('cordis.initHooks')] ?? []) hook()
              await effect(() => instance?.[Symbol.for('cordis.init')]?.())
            } else {
              await effect(() => typeof selected === 'function' ? selected(child, config) : selected.apply(child, config))
            }
            cleanup = disposers.slice(offset)
          })
          tracked(setup)
        }
      }
      return Object.assign(Object.create(fiber), { then: (resolve, reject) => setup.then(() => fiber).then(resolve, reject) })
    }
    const injectServices = (deps, callback) => {
      const names = requiredInject({ inject: deps })
      registrations.push({ inject: names, callback })
      if (names.every(name => store.get(name) !== undefined)) effect(() => callback(buildContext(new Set([...declared, ...names]), {}, target)))
      return { dispose: async () => {} }
    }
    Object.assign(target, {
      logger, get, set, provide, accessor, mixin, effect, plugin, inject: injectServices,
      on, once, emit, parallel, serial, bail, waterfall,
      reflect: { get, set, provide, accessor, mixin },
      registry: { plugin, inject: injectServices },
      events: { on, once, emit, parallel, serial, bail, waterfall },
      fiber: { name: options.name ?? 'release-recorder', effect }, runtime: undefined,
      root, baseUrl: options.baseUrl,
      extend: extra => buildContext(declared, extra, target),
      isolate: () => buildContext(declared, {}, target),
      intercept: () => buildContext(declared, {}, target),
    })
    ctx = new Proxy(target, {
      get(object, key, receiver) {
        if (typeof key === 'symbol' || key === 'prototype' || key === 'then' || key.startsWith('_') || String(parseInt(key)) === key || Reflect.has(object, key)) return Reflect.get(object, key, receiver)
        if (accessors.has(key)) return accessors.get(key).get.call(ctx)
        if (owned.has(key) || declared.has(key)) return store.get(key)
        const error = new Error(`cannot get property "${key}" without inject`)
        refusals.push(error)
        throw error
      },
      has(object, key) { return Reflect.has(object, key) || store.has(key) || accessors.has(key) },
    })
    return ctx
  }

  const ctx = buildContext(new Set(requiredInject({ inject })))
  root = ctx
  ctx.root = ctx
  const drain = async () => {
    while (drained < pending.length) {
      const tasks = pending.slice(drained)
      drained = pending.length
      await Promise.all(tasks)
    }
    if (failures.length) throw new AggregateError(failures, 'release-context:effect-failed')
  }
  const dispose = async () => {
    if (disposed) return
    disposed = true
    let failure
    try { await drain() } catch (error) { failure = error }
    for (const dispose of disposers.splice(0).reverse()) await dispose()
    if (failure) throw failure
  }
  return { ctx, refusals, pending, disposers, logs, registrations, failures, drain, dispose }
}
