/* ScummVM - Graphic Adventure Engine
 *
 * ScummVM is the legal property of its developers, whose names
 * are too numerous to list here. Please refer to the COPYRIGHT
 * file distributed with this source distribution.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "twine/scene/collision.h"
#include "common/debug.h"
#include "common/memstream.h"
#include "common/util.h"
#include "twine/debugger/debug_scene.h"
#include "twine/renderer/renderer.h"
#include "twine/resources/resources.h"
#include "twine/scene/actor.h"
#include "twine/scene/animations.h"
#include "twine/scene/extra.h"
#include "twine/scene/grid.h"
#include "twine/scene/movements.h"
#include "twine/scene/scene.h"
#include "twine/shared.h"
#include "twine/twine.h"

namespace TwinE {

Collision::Collision(TwinEEngine *engine) : _engine(engine) {
}

bool Collision::checkZvOnZv(int32 actorIdx1, int32 actorIdx2) const {
	const ActorStruct *actor1 = _engine->_scene->getActor(actorIdx1);
	const ActorStruct *actor2 = _engine->_scene->getActor(actorIdx2);

	const IVec3 &processActor = actor1->_processActor;
	const IVec3 &mins1 = processActor + actor1->_boundingBox.mins;
	const IVec3 &maxs1 = processActor + actor1->_boundingBox.maxs;

	const IVec3 &mins2 = actor2->posObj() + actor2->_boundingBox.mins;
	const IVec3 &maxs2 = actor2->posObj() + actor2->_boundingBox.maxs;

	if (mins1.x >= maxs2.x) {
		return false;
	}

	if (maxs1.x <= mins2.x) {
		return false;
	}

	if (mins1.y > (maxs2.y + 1)) {
		return false;
	}

	if (mins1.y <= (maxs2.y - SIZE_BRICK_Y)) {
		return false;
	}

	if (maxs1.y <= mins2.y) {
		return false;
	}

	if (mins1.z >= maxs2.z) {
		return false;
	}

	if (maxs1.z <= mins2.z) {
		return false;
	}

	return true;
}

int32 Collision::clampedLerp(int32 val1, int32 val2, int32 nbstep, int32 step) const { // BoundRegleTrois
	if (step <= 0) {
		return val1;
	}

	if (step >= nbstep) {
		return val2;
	}

	return val1 + (((val2 - val1) * step) / nbstep);
}

void Collision::reajustPos(IVec3 &processActor, ShapeType brickShape) const {
	if (brickShape <= ShapeType::kSolid) {
		return;
	}

	const int32 xw = (_collision.x * SIZE_BRICK_XZ) - DEMI_BRICK_XZ;
	const int32 yw = _collision.y * SIZE_BRICK_Y;
	const int32 zw = (_collision.z * SIZE_BRICK_XZ) - DEMI_BRICK_XZ;

	// double-side stairs
	switch (brickShape) {
	case ShapeType::kDoubleSideStairsTop1:
		if (processActor.x - xw < processActor.z - zw) {
			brickShape = ShapeType::kStairsTopRight;
		} else {
			brickShape = ShapeType::kStairsTopLeft;
		}
		break;
	case ShapeType::kDoubleSideStairsBottom1:
		if (processActor.x - xw < processActor.z - zw) {
			brickShape = ShapeType::kStairsBottomRight;
		} else {
			brickShape = ShapeType::kStairsBottomLeft;
		}
		break;
	case ShapeType::kDoubleSideStairsTop2:
		if (processActor.x - xw < processActor.z - zw) {
			brickShape = ShapeType::kStairsTopLeft;
		} else {
			brickShape = ShapeType::kStairsTopRight;
		}
		break;
	case ShapeType::kDoubleSideStairsBottom2:
		if (processActor.x - xw < processActor.z - zw) {
			brickShape = ShapeType::kStairsBottomLeft;
		} else {
			brickShape = ShapeType::kStairsBottomRight;
		}
		break;
	case ShapeType::kDoubleSideStairsLeft1:
		if (SIZE_BRICK_XZ - (processActor.x - xw) > processActor.z - zw) {
			brickShape = ShapeType::kStairsBottomLeft;
		} else {
			brickShape = ShapeType::kStairsTopLeft;
		}
		break;
	case ShapeType::kDoubleSideStairsRight1:
		if (SIZE_BRICK_XZ - (processActor.x - xw) > processActor.z - zw) {
			brickShape = ShapeType::kStairsBottomRight;
		} else {
			brickShape = ShapeType::kStairsTopRight;
		}
		break;
	case ShapeType::kDoubleSideStairsLeft2:
		if (SIZE_BRICK_XZ - (processActor.x - xw) > processActor.z - zw) {
			brickShape = ShapeType::kStairsTopLeft;
		} else {
			brickShape = ShapeType::kStairsBottomLeft;
		}
		break;
	case ShapeType::kDoubleSideStairsRight2:
		if (SIZE_BRICK_XZ - (processActor.x - xw) > processActor.z - zw) {
			brickShape = ShapeType::kStairsTopRight;
		} else {
			brickShape = ShapeType::kStairsBottomRight;
		}
		break;
	default:
		break;
	}

	switch (brickShape) {
	case ShapeType::kStairsTopLeft:
		processActor.y = yw + clampedLerp(0, SIZE_BRICK_Y, SIZE_BRICK_XZ, processActor.x - xw);
		break;
	case ShapeType::kStairsTopRight:
		processActor.y = yw + clampedLerp(0, SIZE_BRICK_Y, SIZE_BRICK_XZ, processActor.z - zw);
		break;
	case ShapeType::kStairsBottomLeft:
		processActor.y = yw + clampedLerp(SIZE_BRICK_Y, 0, SIZE_BRICK_XZ, processActor.z - zw);
		break;
	case ShapeType::kStairsBottomRight:
		processActor.y = yw + clampedLerp(SIZE_BRICK_Y, 0, SIZE_BRICK_XZ, processActor.x - xw);
		break;
	default:
		break;
	}
}

void Collision::handlePushing(const IVec3 &minsTest, const IVec3 &maxsTest, ActorStruct *actor, ActorStruct *actorTest) {
	IVec3 &processActor = actor->_processActor;
	const IVec3 &previousActor = actor->_previousActor;

	const int32 newAngle = _engine->_movements->getAngle(processActor, actorTest->posObj());

	// protect against chain reactions
	if (actorTest->_staticFlags.bCanBePushed && !actor->_staticFlags.bCanBePushed) {
		actorTest->_animStep.y = 0;

		if (actorTest->_staticFlags.bUseMiniZv) {
			if (newAngle >= LBAAngles::ANGLE_45 && newAngle < LBAAngles::ANGLE_135 && actor->_beta >= LBAAngles::ANGLE_45 && actor->_beta < LBAAngles::ANGLE_135) {
				actorTest->_animStep.x = SIZE_BRICK_XZ / 4 + SIZE_BRICK_XZ / 8;
			}
			if (newAngle >= LBAAngles::ANGLE_135 && newAngle < LBAAngles::ANGLE_225 && actor->_beta >= LBAAngles::ANGLE_135 && actor->_beta < LBAAngles::ANGLE_225) {
				actorTest->_animStep.z = -SIZE_BRICK_XZ / 4 + SIZE_BRICK_XZ / 8;
			}
			if (newAngle >= LBAAngles::ANGLE_225 && newAngle < LBAAngles::ANGLE_315 && actor->_beta >= LBAAngles::ANGLE_225 && actor->_beta < LBAAngles::ANGLE_315) {
				actorTest->_animStep.x = -SIZE_BRICK_XZ / 4 + SIZE_BRICK_XZ / 8;
			}
			if ((newAngle >= LBAAngles::ANGLE_315 || newAngle < LBAAngles::ANGLE_45) && (actor->_beta >= LBAAngles::ANGLE_315 || actor->_beta < LBAAngles::ANGLE_45)) {
				actorTest->_animStep.z = SIZE_BRICK_XZ / 4 + SIZE_BRICK_XZ / 8;
			}
		} else {
			actorTest->_animStep.x = processActor.x - actor->_oldPos.x;
			actorTest->_animStep.z = processActor.z - actor->_oldPos.z;
		}
	}

	if ((actorTest->_boundingBox.maxs.x - actorTest->_boundingBox.mins.x == actorTest->_boundingBox.maxs.z - actorTest->_boundingBox.mins.z) &&
		(actor->_boundingBox.maxs.x - actor->_boundingBox.mins.x == actor->_boundingBox.maxs.z - actor->_boundingBox.mins.z)) {
		if (newAngle >= LBAAngles::ANGLE_45 && newAngle < LBAAngles::ANGLE_135) {
			processActor.x = minsTest.x - actor->_boundingBox.maxs.x;
		}
		if (newAngle >= LBAAngles::ANGLE_135 && newAngle < LBAAngles::ANGLE_225) {
			processActor.z = maxsTest.z - actor->_boundingBox.mins.z;
		}
		if (newAngle >= LBAAngles::ANGLE_225 && newAngle < LBAAngles::ANGLE_315) {
			processActor.x = maxsTest.x - actor->_boundingBox.mins.x;
		}
		if (newAngle >= LBAAngles::ANGLE_315 || newAngle < LBAAngles::ANGLE_45) {
			processActor.z = minsTest.z - actor->_boundingBox.maxs.z;
		}
	} else if (!actor->_dynamicFlags.bIsFalling) {
		processActor = previousActor;
	}
}

bool Collision::checkValidObjPos(int32 actorIdx) {
	const ActorStruct *actor = _engine->_scene->getActor(actorIdx);

	const IVec3 m0 = actor->posObj() + actor->_boundingBox.mins;
	const IVec3 m1 = actor->posObj() + actor->_boundingBox.maxs;

	if (m0.x < 0 || m0.x > SIZE_BRICK_XZ * 63) {
		return false;
	}
	if (m1.x < 0 || m1.x > SIZE_BRICK_XZ * 63) {
		return false;
	}
	if (m0.z < 0 || m0.z > SIZE_BRICK_XZ * 63) {
		return false;
	}
	if (m1.z < 0 || m1.z > SIZE_BRICK_XZ * 63) {
		return false;
	}

	Grid *grid = _engine->_grid;
	if (grid->worldColBrickFull(m0.x, m0.y, m0.z, actor->_boundingBox.maxs.y, actorIdx) != ShapeType::kNone) {
		return false;
	}
	if (grid->worldColBrickFull(m1.x, m0.y, m0.z, actor->_boundingBox.maxs.y, actorIdx) != ShapeType::kNone) {
		return false;
	}
	if (grid->worldColBrickFull(m1.x, m0.y, m1.z, actor->_boundingBox.maxs.y, actorIdx) != ShapeType::kNone) {
		return false;
	}
	if (grid->worldColBrickFull(m0.x, m0.y, m1.z, actor->_boundingBox.maxs.y, actorIdx) != ShapeType::kNone) {
		return false;
	}

	for (int32 n = 0; n < _engine->_scene->_sceneNumActors; ++n) {
		const ActorStruct *actorTest = _engine->_scene->getActor(n);
		if (n != actorIdx && actorTest->_body != -1 && !actor->_staticFlags.bIsHidden && actorTest->_carryBy != actorIdx) {
			const IVec3 &t0 = actorTest->posObj() + actorTest->_boundingBox.mins;
			const IVec3 &t1 = actorTest->posObj() + actorTest->_boundingBox.maxs;
			if (m0.x < t1.x && m1.x > t0.x && m0.y < t1.y && m1.y > t0.y && m0.z < t1.z && m1.z > t0.z) {
				return false;
			}
		}
	}
	return true;
}

int32 Collision::checkObjCol(int32 actorIdx) {
	ActorStruct *actor = _engine->_scene->getActor(actorIdx);

	IVec3 &processActor = actor->_processActor;
	IVec3 mins = processActor + actor->_boundingBox.mins;
	IVec3 maxs = processActor + actor->_boundingBox.maxs;

	actor->_collision = -1;

	for (int32 a = 0; a < _engine->_scene->_sceneNumActors; a++) {
		ActorStruct *actorTest = _engine->_scene->getActor(a);

		// avoid current processed actor
		if (a != actorIdx && actorTest->_body != -1 && !actor->_staticFlags.bIsHidden && actorTest->_carryBy != actorIdx) {
			const IVec3 &minsTest = actorTest->posObj() + actorTest->_boundingBox.mins;
			const IVec3 &maxsTest = actorTest->posObj() + actorTest->_boundingBox.maxs;

			if (mins.x < maxsTest.x && maxs.x > minsTest.x && mins.y < maxsTest.y && maxs.y > minsTest.y && mins.z < maxsTest.z && maxs.z > minsTest.z) {
				actor->_collision = a; // mark as collision with actor a

				if (actorTest->_staticFlags.bIsCarrierActor) {
					if (actor->_dynamicFlags.bIsFalling || checkZvOnZv(actorIdx, a)) {
						processActor.y = maxsTest.y - actor->_boundingBox.mins.y + 1;
						actor->_carryBy = a;
						continue;
					}
				} else if (checkZvOnZv(actorIdx, a)) {
					_engine->_actor->hitObj(actorIdx, a, 1, -1);
				}
				handlePushing(minsTest, maxsTest, actor, actorTest);
			}
		}
	}

	if (actor->_dynamicFlags.bIsHitting) {
		const IVec3 &destPos = _engine->_movements->rotate(0, 200, actor->_beta);
		mins = processActor + actor->_boundingBox.mins;
		mins.x += destPos.x;
		mins.z += destPos.z;

		maxs = processActor + actor->_boundingBox.maxs;
		maxs.x += destPos.x;
		maxs.z += destPos.z;

		for (int32 a = 0; a < _engine->_scene->_sceneNumActors; a++) {
			const ActorStruct *actorTest = _engine->_scene->getActor(a);

			// avoid current processed actor
			if (a != actorIdx && actorTest->_body != -1 && !actorTest->_staticFlags.bIsHidden && actorTest->_carryBy != actorIdx) {
				const IVec3 minsTest = actorTest->posObj() + actorTest->_boundingBox.mins;
				const IVec3 maxsTest = actorTest->posObj() + actorTest->_boundingBox.maxs;
				if (mins.x < maxsTest.x && maxs.x > minsTest.x && mins.y < maxsTest.y && maxs.y > minsTest.y && mins.z < maxsTest.z && maxs.z > minsTest.z) {
					_engine->_actor->hitObj(actorIdx, a, actor->_strengthOfHit, actor->_beta + LBAAngles::ANGLE_180);
					actor->_dynamicFlags.bIsHitting = 0;
				}
			}
		}
	}

	return actor->_collision;
}

void Collision::setCollisionPos(const IVec3 &pos) {
	_processCollision = pos;
}

void Collision::doCornerReajustTwinkel(ActorStruct *actor, int32 x, int32 y, int32 z, int32 damageMask) {
	IVec3 &processActor = actor->_processActor;
	IVec3 &previousActor = actor->_previousActor;
	ShapeType brickShape = _engine->_grid->worldColBrick(processActor);

	processActor.x += x;
	processActor.y += y;
	processActor.z += z;

	if (processActor.x >= 0 && processActor.z >= 0 && processActor.x <= SCENE_SIZE_MAX && processActor.z <= SCENE_SIZE_MAX) {
		const BoundingBox &bbox = _engine->_actor->_processActorPtr->_boundingBox;
		reajustPos(processActor, brickShape);
		brickShape = _engine->_grid->worldColBrickFull(processActor, bbox.maxs.y, OWN_ACTOR_SCENE_INDEX);

		if (brickShape == ShapeType::kSolid) {
			_causeActorDamage |= damageMask;
			brickShape = _engine->_grid->worldColBrickFull(processActor.x, processActor.y, previousActor.z + z, bbox.maxs.y, OWN_ACTOR_SCENE_INDEX);

			if (brickShape == ShapeType::kSolid) {
				brickShape = _engine->_grid->worldColBrickFull(x + previousActor.x, processActor.y, processActor.z, bbox.maxs.y, OWN_ACTOR_SCENE_INDEX);

				if (brickShape != ShapeType::kSolid) {
					_processCollision.x = previousActor.x;
				}
			} else {
				_processCollision.z = previousActor.z;
			}
		}
	}

	processActor = _processCollision;
}

void Collision::doCornerReajust(ActorStruct *actor, int32 x, int32 y, int32 z, int32 damageMask) {
	IVec3 &processActor = actor->_processActor;
	IVec3 &previousActor = actor->_previousActor;
	ShapeType brickShape = _engine->_grid->worldColBrick(processActor);

	processActor.x += x;
	processActor.y += y;
	processActor.z += z;

	if (processActor.x >= 0 && processActor.z >= 0 && processActor.x <= SCENE_SIZE_MAX && processActor.z <= SCENE_SIZE_MAX) {
		reajustPos(processActor, brickShape);
		brickShape = _engine->_grid->worldColBrick(processActor);

		if (brickShape == ShapeType::kSolid) {
			_causeActorDamage |= damageMask;
			brickShape = _engine->_grid->worldColBrick(processActor.x, processActor.y, previousActor.z + z);

			if (brickShape == ShapeType::kSolid) {
				brickShape = _engine->_grid->worldColBrick(x + previousActor.x, processActor.y, processActor.z);

				if (brickShape != ShapeType::kSolid) {
					_processCollision.x = previousActor.x;
				}
			} else {
				_processCollision.z = previousActor.z;
			}
		}
	}

	processActor = _processCollision;
}

void Collision::receptionObj(int actorIdx) {
	if (IS_HERO(actorIdx)) {
		const IVec3 &processActor = _engine->_actor->_processActorPtr->_processActor;
		const int32 fall = _engine->_scene->_startYFalling - processActor.y;

		if (fall >= SIZE_BRICK_Y * 8) {
			const IVec3 &actorPos = _engine->_actor->_processActorPtr->posObj();
			_engine->_extra->initSpecial(actorPos.x, actorPos.y + 1000, actorPos.z, ExtraSpecialType::kHitStars);
			if (fall >= SIZE_BRICK_Y * 16) {
				_engine->_actor->_processActorPtr->setLife(0);
			} else {
				_engine->_actor->_processActorPtr->addLife(-1);
			}
			_engine->_animations->initAnim(AnimationTypes::kLandingHit, AnimType::kAnimationAllThen, AnimationTypes::kStanding, actorIdx);
		} else if (fall > 2 * SIZE_BRICK_Y) {
			_engine->_animations->initAnim(AnimationTypes::kLanding, AnimType::kAnimationAllThen, AnimationTypes::kStanding, actorIdx);
		} else {
			if (_engine->_actor->_processActorPtr->_dynamicFlags.bWasWalkingBeforeFalling) {
				// try to not interrupt walk animation if Twinsen falls down from small height
				_engine->_animations->initAnim(AnimationTypes::kForward, AnimType::kAnimationTypeRepeat, AnimationTypes::kStanding, actorIdx);
			} else {
				_engine->_animations->initAnim(AnimationTypes::kStanding, AnimType::kAnimationTypeRepeat, AnimationTypes::kStanding, actorIdx);
			}
		}

		_engine->_scene->_startYFalling = 0;
	} else {
		_engine->_animations->initAnim(AnimationTypes::kLanding, AnimType::kAnimationAllThen, _engine->_actor->_processActorPtr->_nextGenAnim, actorIdx);
	}

	_engine->_actor->_processActorPtr->_dynamicFlags.bIsFalling = 0;
	_engine->_actor->_processActorPtr->_dynamicFlags.bWasWalkingBeforeFalling = 0;
}

int32 Collision::extraCheckObjCol(ExtraListStruct *extra, int32 actorIdx) {
	const BoundingBox *bbox = _engine->_resources->_spriteBoundingBox.bbox(extra->sprite);
	const IVec3 mins = bbox->mins + extra->pos;
	const IVec3 maxs = bbox->maxs + extra->pos;

	for (int32 a = 0; a < _engine->_scene->_sceneNumActors; a++) {
		const ActorStruct *actorTest = _engine->_scene->getActor(a);

		if (a != actorIdx && actorTest->_body != -1) {
			const IVec3 minsTest = actorTest->posObj() + actorTest->_boundingBox.mins;
			const IVec3 maxsTest = actorTest->posObj() + actorTest->_boundingBox.maxs;

			if (mins.x < maxsTest.x && maxs.x > minsTest.x && mins.y < maxsTest.y && maxs.y > minsTest.y && mins.z < maxsTest.z && maxs.z > minsTest.z) {
				if (extra->strengthOfHit != 0) {
					_engine->_actor->hitObj(actorIdx, a, extra->strengthOfHit, -1);
				}

				return a;
			}
		}
	}

	return -1;
}

bool Collision::fullWorldColBrick(int32 x, int32 y, int32 z, const IVec3 &oldPos) {
	if (_engine->_grid->worldColBrick(oldPos) != ShapeType::kNone) {
		return true;
	}

	const int32 averageX = ABS(x + oldPos.x) / 2;
	const int32 averageY = ABS(y + oldPos.y) / 2;
	const int32 averageZ = ABS(z + oldPos.z) / 2;

	if (_engine->_grid->worldColBrick(averageX, averageY, averageZ) != ShapeType::kNone) {
		return true;
	}

	if (_engine->_grid->worldColBrick(ABS(oldPos.x + averageX) / 2, ABS(oldPos.y + averageY) / 2, ABS(oldPos.z + averageZ) / 2) != ShapeType::kNone) {
		return true;
	}

	if (_engine->_grid->worldColBrick(ABS(x + averageX) / 2, ABS(y + averageY) / 2, ABS(z + averageZ) / 2) != ShapeType::kNone) {
		return true;
	}

	return false;
}

int32 Collision::extraCheckExtraCol(ExtraListStruct *extra, int32 extraIdx) const {
	int32 index = extra->sprite;
	const BoundingBox *bbox = _engine->_resources->_spriteBoundingBox.bbox(index);
	const IVec3 mins = bbox->mins + extra->pos;
	const IVec3 maxs = bbox->maxs + extra->pos;

	for (int32 i = 0; i < EXTRA_MAX_ENTRIES; i++) {
		const ExtraListStruct *extraTest = &_engine->_extra->_extraList[i];
		if (i != extraIdx && extraTest->sprite != -1) {
			const BoundingBox *testbbox = _engine->_resources->_spriteBoundingBox.bbox(++index);
			const IVec3 minsTest = testbbox->mins + extraTest->pos;
			const IVec3 maxsTest = testbbox->maxs + extraTest->pos;

			if (mins.x >= minsTest.x) {
				continue;
			}
			if (mins.x < maxsTest.x && maxs.x > minsTest.x && mins.y < maxsTest.y && maxs.y > minsTest.y && mins.z < maxsTest.z && maxs.z > minsTest.z) {
				return i;
			}
		}
	}

	return -1;
}

} // namespace TwinE
