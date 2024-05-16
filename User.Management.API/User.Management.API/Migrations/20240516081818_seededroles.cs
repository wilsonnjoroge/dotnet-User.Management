using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace User.Management.API.Migrations
{
    /// <inheritdoc />
    public partial class seededroles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "3bb77e4e-081a-4969-96d0-5a1b72d5f115");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "908919ac-de66-4712-9a9e-098f0b8c191d");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "972ced24-2e49-43ae-bad7-e13806108de3");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "2fcb9512-6ac3-4560-98ab-3ee1cddf50dc", "2", "User", "User" },
                    { "c4da8331-085a-4cef-afe5-e8a287fa77e5", "3", "HR", "HR" },
                    { "c803a2ba-9be1-4ee2-ae23-1014eb014af8", "1", "Admin", "Admin" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "2fcb9512-6ac3-4560-98ab-3ee1cddf50dc");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "c4da8331-085a-4cef-afe5-e8a287fa77e5");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "c803a2ba-9be1-4ee2-ae23-1014eb014af8");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "3bb77e4e-081a-4969-96d0-5a1b72d5f115", "3", "HR", "HR" },
                    { "908919ac-de66-4712-9a9e-098f0b8c191d", "2", "User", "User" },
                    { "972ced24-2e49-43ae-bad7-e13806108de3", "1", "Admin", "Admin" }
                });
        }
    }
}
