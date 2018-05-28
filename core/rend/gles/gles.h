#pragma once
#include "rend/rend.h"
#include <map>

#ifdef GLES
#if defined(TARGET_IPHONE) //apple-specific ogles2 headers
//#include <APPLE/egl.h>
#include <OpenGLES/ES2/gl.h>
#include <OpenGLES/ES2/glext.h>
#else
#if !defined(TARGET_NACL32)
#include <EGL/egl.h>
#endif
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#endif

#ifndef GL_NV_draw_path
//IMGTEC GLES emulation
#pragma comment(lib,"libEGL.lib")
#pragma comment(lib,"libGLESv2.lib")
#else /* NV gles emulation*/
#pragma comment(lib,"libGLES20.lib")
#endif

#else
#if HOST_OS == OS_DARWIN
    #include <OpenGL/gl3.h>
#else
	#include <GL3/gl3w.h>
#endif
#endif


#define glCheck() do { if (unlikely(settings.validate.OpenGlChecks)) { verify(glGetError()==GL_NO_ERROR); } } while(0)
#define eglCheck() false

#define VERTEX_POS_ARRAY 0
#define VERTEX_COL_BASE_ARRAY 1
#define VERTEX_COL_OFFS_ARRAY 2
#define VERTEX_UV_ARRAY 3


//vertex types
extern u32 gcflip;
extern float scale_x, scale_y;


void DrawStrips();

struct PipelineShader
{
	GLuint program;

	GLuint scale,depth_scale;
	GLuint pp_ClipTest,cp_AlphaTestValue;
	GLuint sp_FOG_COL_RAM,sp_FOG_COL_VERT,sp_FOG_DENSITY,sp_LOG_FOG_COEFS;
	GLuint shade_scale_factor;
	GLuint screen_size;
	GLuint blend_mode;
	GLuint pp_Number;

	//
	u32 cp_AlphaTest; s32 pp_ClipTestMode;
	u32 pp_Texture, pp_UseAlpha, pp_IgnoreTexA, pp_ShadInstr, pp_Offset, pp_FogCtrl;
	int pass;
};


struct gl_ctx
{
#if defined(GLES) && HOST_OS != OS_DARWIN && !defined(TARGET_NACL32)
	struct
	{
		EGLNativeWindowType native_wind;
		EGLNativeDisplayType native_disp;
		EGLDisplay display;
		EGLSurface surface;
		EGLContext context;
	} setup;
#endif

	struct
	{
		GLuint program;

		GLuint scale,depth_scale;
	} modvol_shader;

	std::map<int, PipelineShader *> shaders;
	struct
	{
		GLuint program,scale,depth_scale;
	} OSD_SHADER;

	struct
	{
		GLuint geometry,modvols,idxs,idxs2;
#ifndef GLES
		GLuint vao;
#endif
	} vbo;

	PipelineShader *getShader(int programId) {
		PipelineShader *shader = shaders[programId];
		if (shader == NULL) {
			shader = new PipelineShader();
			shaders[programId] = shader;
			shader->program = -1;
		}
		return shader;
	}
};

extern gl_ctx gl;

GLuint gl_GetTexture(TSP tsp,TCW tcw);
struct text_info {
	u16* pdata;
	u32 width;
	u32 height;
	u32 textype; // 0 565, 1 1555, 2 4444
};

text_info raw_GetTexture(TSP tsp, TCW tcw);
void CollectCleanup();
void DoCleanup();
void SortPParams(int first, int count);

extern int screen_width;
extern int screen_height;

void BindRTT(u32 addy, u32 fbw, u32 fbh, u32 channels, u32 fmt);
void ReadRTTBuffer();
int GetProgramID(u32 cp_AlphaTest, u32 pp_ClipTestMode,
							u32 pp_Texture, u32 pp_UseAlpha, u32 pp_IgnoreTexA, u32 pp_ShadInstr, u32 pp_Offset,
							u32 pp_FogCtrl, int pass);

struct ShaderUniforms_t
{
	float PT_ALPHA;
	float scale_coefs[4];
	float depth_coefs[4];
	float fog_den_float;
	float ps_FOG_COL_RAM[3];
	float ps_FOG_COL_VERT[3];
	float fog_coefs[2];
	GLuint blend_mode[2];
	int poly_number;

	void Set(PipelineShader* s)
	{
		if (s->cp_AlphaTestValue!=-1)
			glUniform1f(s->cp_AlphaTestValue,PT_ALPHA);

		if (s->scale!=-1)
			glUniform4fv( s->scale, 1, scale_coefs);

		if (s->depth_scale!=-1)
			glUniform4fv( s->depth_scale, 1, depth_coefs);

		if (s->sp_FOG_DENSITY!=-1)
			glUniform1f( s->sp_FOG_DENSITY,fog_den_float);

		if (s->sp_FOG_COL_RAM!=-1)
			glUniform3fv( s->sp_FOG_COL_RAM, 1, ps_FOG_COL_RAM);

		if (s->sp_FOG_COL_VERT!=-1)
			glUniform3fv( s->sp_FOG_COL_VERT, 1, ps_FOG_COL_VERT);

		if (s->sp_LOG_FOG_COEFS!=-1)
			glUniform2fv(s->sp_LOG_FOG_COEFS,1, fog_coefs);

		if (s->screen_size != -1)
			glUniform2f(s->screen_size, (float)screen_width, (float)screen_height);

		if (s->shade_scale_factor != -1)
			glUniform1f(s->shade_scale_factor, FPU_SHAD_SCALE.scale_factor / 256.f);

		if (s->blend_mode != -1)
			glUniform2uiv(s->blend_mode, 1, blend_mode);

		if (s->pp_Number != -1)
			glUniform1i(s->pp_Number, poly_number);
	}

};
extern ShaderUniforms_t ShaderUniforms;

extern const char *PixelPipelineShader;
bool CompilePipelineShader(PipelineShader* s, const char *source = PixelPipelineShader);
#define TEXTURE_LOAD_ERROR 0
GLuint loadPNG(const string& subpath, int &width, int &height);

extern GLuint stencilTexId;
extern GLuint depthTexId;
extern GLuint opaqueTexId;

// Must match!
#define ABUFFER_SIZE 32
#define ABUFFER_SIZE_STR "32"
