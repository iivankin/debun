pub(super) fn runtime_source() -> &'static str {
    r#"function copyProps(target, source, reexportTarget) {
  const propertyNames = Object.getOwnPropertyNames(source);
  for (const propertyName of propertyNames) {
    if (!Object.prototype.hasOwnProperty.call(target, propertyName) && propertyName !== "default") {
      Object.defineProperty(target, propertyName, {
        get: () => source[propertyName],
        enumerable: true
      });
    }
  }
  if (!reexportTarget) {
    return;
  }
  for (const propertyName of propertyNames) {
    if (!Object.prototype.hasOwnProperty.call(reexportTarget, propertyName) && propertyName !== "default") {
      Object.defineProperty(reexportTarget, propertyName, {
        get: () => source[propertyName],
        enumerable: true
      });
    }
  }
  return reexportTarget;
}

const toESMCache = new WeakMap();
const toESMNodeCache = new WeakMap();

function toESM(value, isNodeMode, target) {
  const isObjectLike = value != null && typeof value === "object";
  if (isObjectLike) {
    const cache = isNodeMode ? toESMNodeCache : toESMCache;
    const cached = cache.get(value);
    if (cached) {
      return cached;
    }
    target = Object.create(Object.getPrototypeOf(value));
    const namespace = isNodeMode || !value || !value.__esModule ? Object.defineProperty(target, "default", {
      value,
      enumerable: true
    }) : target;
    for (const propertyName of Object.getOwnPropertyNames(value)) {
      if (!Object.prototype.hasOwnProperty.call(namespace, propertyName)) {
        Object.defineProperty(namespace, propertyName, {
          get: () => value[propertyName],
          enumerable: true
        });
      }
    }
    cache.set(value, namespace);
    return namespace;
  }
  target = value != null ? Object.create(Object.getPrototypeOf(value)) : {};
  return isNodeMode || !value || !value.__esModule ? Object.defineProperty(target, "default", {
    value,
    enumerable: true
  }) : target;
}

const toCommonJSCache = new WeakMap();

function toCommonJS(value) {
  const cached = toCommonJSCache.get(value);
  if (cached) {
    return cached;
  }
  const namespace = Object.defineProperty({}, "__esModule", { value: true });
  if ((value && typeof value === "object") || typeof value === "function") {
    for (const propertyName of Object.getOwnPropertyNames(value)) {
      if (!Object.prototype.hasOwnProperty.call(namespace, propertyName)) {
        const descriptor = Object.getOwnPropertyDescriptor(value, propertyName);
        Object.defineProperty(namespace, propertyName, {
          get: () => value[propertyName],
          enumerable: !descriptor || descriptor.enumerable
        });
      }
    }
  }
  toCommonJSCache.set(value, namespace);
  return namespace;
}

function defineExports(target, spec) {
  for (const propertyName in spec) {
    Object.defineProperty(target, propertyName, {
      get: spec[propertyName],
      enumerable: true,
      configurable: true,
      set(value) {
        spec[propertyName] = () => value;
      }
    });
  }
}

function createLazyInit(init) {
  let initialized = false;
  let cache;
  return function initOnce() {
    if (initialized) {
      return cache;
    }
    initialized = true;
    cache = init();
    return cache;
  };
}

module.exports = {
  copyProps,
  createLazyInit,
  defineExports,
  toCommonJS,
  toESM
};
"#
}
