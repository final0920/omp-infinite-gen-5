/**
 * 把 IG5 工具定义里的 JSON Schema 转成 omp 能接受的 zod schema。
 *
 * IG5 的工具参数本来就是 JSON Schema（dsh 侧直接吃），omp 的 registerTool 只收
 * zod / typebox / arktype。这里只覆盖 IG5 实际用到的那部分关键字；遇到不认识的
 * 组合就放宽成 z.unknown()，让引擎自己按原有校验拒绝，避免把合法参数挡在宿主层。
 */

const has = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

function literalOf(z, value) {
	if (value === null) return z.null();
	if (Array.isArray(value)) return z.array(z.unknown());
	if (typeof value === 'object') return z.unknown();
	return z.literal(value);
}

function enumSchema(z, values, description) {
	const unique = [...new Set(values)];
	if (!unique.length) return describe(z.string(), description);
	if (unique.every((value) => typeof value === 'string')) return describe(z.enum(unique), description);
	// omptype 的 zod 层不接受无序 union（"overlapping morph inputs"），数值枚举只能退化成带说明的 number
	if (unique.every((value) => typeof value === 'number')) {
		const integers = unique.every((value) => Number.isInteger(value));
		const schema = integers ? z.number().int() : z.number();
		const hint = `${description ? `${description} ` : ''}可选值: ${unique.join(', ')}`;
		return describe(schema, hint);
	}
	return describe(z.unknown(), description);
}

function describe(schema, description) {
	if (!description || typeof schema?.describe !== 'function') return schema;
	return schema.describe(description);
}

/** 递归转换：node 为空或形态未知时返回 unknown，调用方据此保留宽松语义。 */
export function jsonSchemaToZod(z, node) {
	if (!node || typeof node !== 'object') return z.unknown();
	const description = typeof node.description === 'string' ? node.description : undefined;

	if (Array.isArray(node.enum)) return enumSchema(z, node.enum, description);
	if (has(node, 'const')) return describe(literalOf(z, node.const), description);

	const variants = node.oneOf ?? node.anyOf;
	if (Array.isArray(variants) && variants.length === 1) return jsonSchemaToZod(z, variants[0]);
	// 多分支 union 在 omptype 里同样受限，交给引擎按原 JSON Schema 校验，宿主层只放宽
	if (Array.isArray(variants) && variants.length) return describe(z.unknown(), description);

	const types = Array.isArray(node.type) ? node.type : node.type ? [node.type] : [];
	const nullable = types.includes('null');
	const primary = types.find((type) => type !== 'null');

	let schema;
	if (primary === 'object' || (!primary && node.properties)) {
		schema = objectSchema(z, node);
	} else if (primary === 'array') {
		const items = Array.isArray(node.items) ? z.unknown() : jsonSchemaToZod(z, node.items);
		schema = z.array(items ?? z.unknown());
		if (Number.isSafeInteger(node.minItems)) schema = schema.min(node.minItems);
		if (Number.isSafeInteger(node.maxItems)) schema = schema.max(node.maxItems);
	} else if (primary === 'integer') {
		schema = z.number().int();
		if (typeof node.minimum === 'number') schema = schema.min(node.minimum);
		if (typeof node.maximum === 'number') schema = schema.max(node.maximum);
	} else if (primary === 'number') {
		schema = z.number();
		if (typeof node.minimum === 'number') schema = schema.min(node.minimum);
		if (typeof node.maximum === 'number') schema = schema.max(node.maximum);
	} else if (primary === 'boolean') {
		schema = z.boolean();
	} else if (primary === 'string') {
		schema = z.string();
		if (Number.isSafeInteger(node.minLength)) schema = schema.min(node.minLength);
		if (Number.isSafeInteger(node.maxLength)) schema = schema.max(node.maxLength);
		if (typeof node.pattern === 'string') {
			try { schema = schema.regex(new RegExp(node.pattern)); } catch { /* 非法正则交给引擎判断，宿主层不收紧 */ }
		}
	} else {
		schema = z.unknown();
	}

	return describe(nullable && typeof schema.nullable === 'function' ? schema.nullable() : schema, description);
}

function objectSchema(z, node) {
	const properties = node.properties && typeof node.properties === 'object' ? node.properties : {};
	const required = new Set(Array.isArray(node.required) ? node.required : []);
	const shape = {};
	for (const [key, value] of Object.entries(properties)) {
		let field = jsonSchemaToZod(z, value);
		if (!required.has(key)) field = field.optional();
		shape[key] = field;
	}
	let schema = z.object(shape);
	// additionalProperties !== false 时保留额外键，否则 omp 会按严格对象剥掉它们
	if (node.additionalProperties !== false && typeof schema.passthrough === 'function') schema = schema.passthrough();
	return schema;
}
