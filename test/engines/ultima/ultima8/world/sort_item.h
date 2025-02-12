#include <cxxtest/TestSuite.h>
#include "engines/ultima/ultima8/world/sort_item.h"

/**
 * Test suite for the functions in engines/ultima/ultima8/world/sort_item.h
 *
 * Be aware that the x and y coordinates go opposite to what you might expect,
 * see the notes in sort_item.h
 *
 * Still TODO tests:
 *  * overlapping in various dimensions
 *  * flat (z == zTop) items with various flags
 *  * special case for crusader inventory items
 *  * items that are flat in x or y (what should these do?)
 */
class U8SortItemTestSuite : public CxxTest::TestSuite {
	public:
	U8SortItemTestSuite() {
	}

	/* Non-overlapping with lower Y position should always be below */
	void test_basic_y_sort() {
		Ultima::Ultima8::SortItem si1(nullptr);
		Ultima::Ultima8::SortItem si2(nullptr);

		si1._yFar = 0;
		si1._y = 10;
		si2._yFar = 20;
		si2._y = 30;
		si1._x = si2._x = 10;
		TS_ASSERT(si1.below(si2));
		TS_ASSERT(!si2.below(si1));
	}

	/* Non-overlapping with lower X position should always be below */
	void test_basic_x_sort() {
		Ultima::Ultima8::SortItem si1(nullptr);
		Ultima::Ultima8::SortItem si2(nullptr);

		si1._y = si2._y = 10;
		si1._x = 10;
		si2._xLeft = 20;
		si2._x = 30;
		TS_ASSERT(si1.below(si2));
		TS_ASSERT(!si2.below(si1));
	}

	/* Non-overlapping with lower Z position should always be below */
	void test_basic_z_sort() {
		Ultima::Ultima8::SortItem si1(nullptr);
		Ultima::Ultima8::SortItem si2(nullptr);

		si1._x = si2._x = si1._y = si2._y = 10;
		si1._zTop = 10;
		si2._z = 20;
		si2._zTop = 30;
		TS_ASSERT(si1.below(si2));
		TS_ASSERT(!si2.below(si1));
	}

	/* Sprites should always be at the top regardless of x/y/z */
	void test_sprite_sort() {
		Ultima::Ultima8::SortItem si1(nullptr);
		Ultima::Ultima8::SortItem si2(nullptr);

		si2._sprite = true;
		TS_ASSERT(si1.below(si2));
		TS_ASSERT(!si2.below(si1));

		si2._x = si2._xLeft = si1._y = si2._yFar = 10;
		si2._z = 20;
		si2._zTop = 30;
		TS_ASSERT(si1.below(si2));
		TS_ASSERT(!si2.below(si1));
	}

	/* Overlapping flat items (generally the floor) follow a set of rules */
	void test_flat_sort() {
		Ultima::Ultima8::SortItem si1(nullptr);
		Ultima::Ultima8::SortItem si2(nullptr);

		si1._x = si2._x = si1._y = si2._y = 10;

		si1._flat = true;
		si2._flat = true;

		// If one has a higher z, it's above
		si2._z = 1;
		TS_ASSERT(si1.below(si2));
		TS_ASSERT(!si2.below(si1));
		si2._z = 0;

		// Animated always gets drawn above
		si1._anim = true;
		TS_ASSERT(si2.below(si1));
		TS_ASSERT(!si1.below(si2));
		si1._anim = false;

		// Trans always gets drawn above
		si1._trans = true;
		TS_ASSERT(si2.below(si1));
		TS_ASSERT(!si1.below(si2));
		si1._trans = false;

		// Draw always gets drawn below
		si1._draw = true;
		TS_ASSERT(si1.below(si2));
		TS_ASSERT(!si2.below(si1));
		si1._draw = false;

		// Solid always gets drawn below
		si1._solid = true;
		TS_ASSERT(si1.below(si2));
		TS_ASSERT(!si2.below(si1));
		si1._solid = false;

		// Occludes always get drawn below
		si1._occl = true;
		TS_ASSERT(si1.below(si2));
		TS_ASSERT(!si2.below(si1));
		si1._occl = false;

		// Large flat squares get drawn below
		si1._fbigsq = true;
		TS_ASSERT(si1.below(si2));
		TS_ASSERT(!si2.below(si1));
		si1._fbigsq = false;
	}

	/* Overlapping non-flat items also follow a set of rules */
	void test_non_flat_sort() {
		Ultima::Ultima8::SortItem si1(nullptr);
		Ultima::Ultima8::SortItem si2(nullptr);

		// Land always gets drawn below
		// MainActor::teleport 6 7642 19776 48
		si1._x = 128;
		si1._y = 32;
		si1._z = 0;
		si1._xLeft = 0;
		si1._yFar = 0;
		si1._zTop = 8;
		si1._occl = true;
		si1._roof = true;
		si1._land = true;

		si2._x = 92;
		si2._y = 64;
		si2._z = 0;
		si2._xLeft = 28;
		si2._yFar = 0;
		si2._zTop = 40;
		si2._solid = true;
		TS_ASSERT(si1.below(si2));
		TS_ASSERT(!si2.below(si1));
	}

	/**
	 * Overlapping non-flat items draw transparent after
	 * Test case for rendering issue at MainActor::teleport 41 17627 16339 48
	 * Wall with window should render after non-window wall
	 */
	void test_nonflat_tranparent_sort() {
		Ultima::Ultima8::SortItem si1(nullptr);
		Ultima::Ultima8::SortItem si2(nullptr);

		si1._x = 32;
		si1._y = 96;
		si1._z = 0;
		si1._xLeft = 0;
		si1._yFar = 0;
		si1._zTop = 40;
		si1._solid = true;

		si2._x = 32;
		si2._y = 160;
		si2._z = 0;
		si2._xLeft = 0;
		si2._yFar = 32;
		si2._zTop = 40;
		si2._trans = true;
		si2._solid = true;
		si2._land = true;

		TS_ASSERT(si1.below(si2));
		TS_ASSERT(!si2.below(si1));
	}

	/**
	 * Overlapping y-flat vs non-flat items
	 * Test case for rendering issue at MainActor::teleport 41 20063 13887 48
	 */
	void test_y_flat_sort() {
		Ultima::Ultima8::SortItem si1(nullptr);
		Ultima::Ultima8::SortItem si2(nullptr);

		si1._x = 64;
		si1._y = 0;
		si1._z = 16;
		si1._xLeft = 0;
		si1._yFar = 0;
		si1._zTop = 32;
		si1._solid = true;

		si2._x = 64;
		si2._y = 64;
		si2._z = 0;
		si2._xLeft = 0;
		si2._yFar = 0;
		si2._zTop = 40;
		si2._solid = true;

		TS_ASSERT(si1.below(si2));
		TS_ASSERT(!si2.below(si1));
	}

	/**
	 * Overlapping non-flat items clearly in z - avatar above candle
	 * Test case for rendering issue at MainActor::teleport 6 7774 19876 48
	 */
	void test_nonflat_z_clear_sort() {
		Ultima::Ultima8::SortItem si1(nullptr);
		Ultima::Ultima8::SortItem si2(nullptr);

		si1._x = 129;
		si1._y = 32;
		si1._z = 0;
		si1._xLeft = 65;
		si1._yFar = 0;
		si1._zTop = 24;
		si1._anim = true;
		si1._solid = true;

		si2._x = 64;
		si2._y = 69;
		si2._z = 24;
		si2._xLeft = 0;
		si2._yFar = 5;
		si2._zTop = 64;
		si2._solid = true;

		TS_ASSERT(si1.below(si2));
		TS_ASSERT(!si2.below(si1));
	}

	/* Overlapping non-flat occludes flat */
	void test_basic_occludes() {
		Ultima::Ultima8::SortItem si1(nullptr);
		Ultima::Ultima8::SortItem si2(nullptr);

		si1._xLeft = si2._xLeft = 0;
		si1._yFar = si2._yFar = 0;
		si1._z = si2._z = 0;
		si1._y = si2._y = 128;
		si1._x = si2._x = 128;
		si1._zTop = 16;
		si2._zTop = 0;
		si1.calculateBoxBounds(0, 0);
		si2.calculateBoxBounds(0, 0);

		TS_ASSERT(si1.occludes(si2));
		TS_ASSERT(!si2.occludes(si1));
	}

	/**
	 * Overlapping non-flat does occlude flat due to frame offset
	 * Test case for rendering issue at MainActor::teleport 49 19167 17582 48
	 */
	void test_frame_offset_occludes() {
		Ultima::Ultima8::SortItem si1(nullptr);
		Ultima::Ultima8::SortItem si2(nullptr);

		si1._xLeft = si2._xLeft = 0;
		si1._yFar = si2._yFar = 0;
		si1._z = si2._z = 0;
		si1._y = si2._y = 128;
		si1._x = si2._x = 128;
		si1._zTop = 16;
		si2._zTop = 0;

		si1.calculateBoxBounds(0, 0);
		si2.calculateBoxBounds(0, 0);

		// ShapeFrame (240:1)
		si1._sx = si1._sxBot - 32;
		si1._sy = si1._syBot - 48;
		si1._sx2 = si1._sx + 65;
		si1._sy2 = si1._sy + 48;

		// ShapeFrame (301:1)
		si2._sx = si2._sxBot - 31;
		si2._sy = si2._syBot - 31;
		si2._sx2 = si2._sx + 62;
		si2._sy2 = si2._sy + 32;

		// FIXME: This case fails here currently
		//TS_ASSERT(!si1.occludes(si2));
		TS_ASSERT(!si2.occludes(si1));
	}
};
