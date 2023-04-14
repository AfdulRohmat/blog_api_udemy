<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('articles', function (Blueprint $table) {
            $table->id();
            // id user
            $table->unsignedBigInteger('user_id');

            // id category
            $table->unsignedBigInteger('category_id');

            $table->string('title');
            $table->string('slug')->unique();
            $table->string('content_preview');
            $table->text('content');
            $table->string('featured_image');
            $table->timestamps();
            $table->softDeletes();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('articles');
    }
};
