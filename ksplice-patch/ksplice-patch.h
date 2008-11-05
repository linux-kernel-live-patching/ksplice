#ifndef _KSPLICE_PATCH_H
#define _KSPLICE_PATCH_H

enum ksplice_option_type {
	KSPLICE_OPTION_ASSUME_RODATA,
};

struct ksplice_option {
	enum ksplice_option_type type;
	const void *target;
};

#ifdef __KERNEL__
#ifndef __used
#define __used __attribute_used__
#endif

#define ksplice_call_int(name, fn) \
	static typeof(int (*)(void)) __ksplice_##name##_##fn __used \
	__attribute__((__section__(".ksplice_call_" #name))) = fn

#define ksplice_call_void(name, fn) \
	static typeof(void (*)(void)) __ksplice_##name##_##fn __used \
	__attribute__((__section__(".ksplice_call_" #name))) = fn

#define ksplice_pre_apply(fn) ksplice_call_int(pre_apply, fn)
#define ksplice_check_apply(fn) ksplice_call_int(check_apply, fn)
#define ksplice_apply(fn) ksplice_call_void(apply, fn)
#define ksplice_post_apply(fn) ksplice_call_void(post_apply, fn)
#define ksplice_fail_apply(fn) ksplice_call_void(fail_apply, fn)

#define ksplice_pre_reverse(fn) ksplice_call_int(pre_reverse, fn)
#define ksplice_check_reverse(fn) ksplice_call_int(check_reverse, fn)
#define ksplice_reverse(fn) ksplice_call_void(reverse, fn)
#define ksplice_post_reverse(fn) ksplice_call_void(post_reverse, fn)
#define ksplice_fail_reverse(fn) ksplice_call_void(fail_reverse, fn)

#define ksplice_assume_rodata(obj)				\
	const struct ksplice_option				\
	__used __attribute__((__section__(".ksplice_options")))	\
	assume_rodata_##obj = {					\
		.type = KSPLICE_OPTION_ASSUME_RODATA,		\
		.target = (const void *)&obj,			\
	}

int init_shadow_field_type(int *shadow_key, typeof(GFP_KERNEL) gfp_flags);
void *init_shadow_field(int *shadow_key, void *obj, int size,
			typeof(GFP_KERNEL) gfp_flags);
void cleanup_shadow_field(int *shadow_key, void *obj);
void *get_shadow_field(int *shadow_key, void *obj);
void cleanup_shadow_field_type(int *shadow_key);


#define __DEFINE_SHADOW_FIELD(base_type, field_type, gfp_flags,			\
			      init_field_type_fn, init_field_fn, get_field_fn,	\
			      make_field_fn, cleanup_field_fn,			\
			      cleanup_field_type_fn, shadow_key, init_field)	\
	static int shadow_key = 0;						\
	int init_field_type_fn(void)						\
	{									\
		return init_shadow_field_type(&shadow_key, gfp_flags);		\
	}									\
	field_type *init_field_fn(base_type *obj, typeof(GFP_KERNEL) flags)	\
	{									\
		field_type *data = init_shadow_field(&shadow_key, (void *)obj,	\
						     sizeof(*data), flags);	\
		if (data != NULL)						\
			init_field(data);					\
		return data;							\
	}									\
	void cleanup_field_fn(base_type *obj)					\
	{									\
		cleanup_shadow_field(&shadow_key, obj);				\
	}									\
	field_type *get_field_fn(base_type *obj)				\
	{									\
		return get_shadow_field(&shadow_key, obj);			\
	}									\
	field_type *make_field_fn(base_type *obj, typeof(GFP_KERNEL) flags)	\
	{									\
		void *data = get_shadow_field(&shadow_key, (void *)obj);	\
		if (data == NULL)						\
			data = init_field_fn(obj, flags);		\
		return data;							\
	}									\
	void cleanup_field_type_fn(void)					\
	{									\
		return cleanup_shadow_field_type(&shadow_key);			\
	}									\
	struct eat_trailing_semicolon

#define DEFINE_SHADOW_FIELD(base_type, field_type, gfp_flags, name, init_field)	\
	__DEFINE_SHADOW_FIELD(base_type, field_type, gfp_flags,			\
			      init_##name##_shadows, init_##name##_shadow,	\
			      get_##name##_shadow, make_##name##_shadow,	\
			      cleanup_##name##_shadow, cleanup_##name##_shadows,\
			      shadow_key_##name, init_field);			\
	ksplice_check_apply(init_##name##_shadows);				\
	ksplice_post_reverse(cleanup_##name##_shadows);				\
	ksplice_fail_apply(cleanup_##name##_shadows)

#define __DECLARE_SHADOW_FIELD(base_type, field_type, init_field_type_fn,	\
			       init_field_fn, get_field_fn, make_field_fn,	\
			       cleanup_field_fn, cleanup_field_type_fn)		\
	int init_field_type_fn(void);						\
	field_type *init_field_fn(base_type *obj, typeof(GFP_KERNEL) flags);	\
	void cleanup_field_fn(base_type *obj);					\
	field_type *get_field_fn(base_type *obj);				\
	field_type *make_field_fn(base_type *obj, typeof(GFP_KERNEL) flags);	\
	void cleanup_field_type_fn(void)

#define DECLARE_SHADOW_FIELD(base_type, field_type, name)			\
	__DECLARE_SHADOW_FIELD(base_type, field_type, init_##name##_shadows,	\
			       init_##name##_shadow, get_##name##_shadow,	\
			       make_##name##_shadow, cleanup_##name##_shadow,	\
			       cleanup_##name##_shadows)

#endif /* __KERNEL__ */

#endif /* _KSPLICE_PATCH_H */
